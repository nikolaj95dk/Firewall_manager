//! Reading and modifying Windows Firewall rules.
//!
//! Rules are read straight from the firewall's registry store: it is fast and, unlike the
//! COM API, exposes each rule's unique ID (display names are frequently duplicated).
//! Deleting / toggling goes through the NetSecurity PowerShell module addressed by that ID,
//! so the exact rule is hit even when several share a name. New rules are created via COM.

use std::collections::{HashMap, HashSet};
use std::io::Write as _;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use windows::core::{BSTR, PCWSTR};
use windows::Win32::Foundation::{VARIANT_FALSE, VARIANT_TRUE};
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, NetFwPolicy2, NetFwRule, NET_FW_ACTION, NET_FW_PROFILE_TYPE2,
    NET_FW_RULE_DIRECTION,
};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED,
};
use windows::Win32::UI::Shell::SHLoadIndirectString;
use winreg::enums::HKEY_LOCAL_MACHINE;
use winreg::types::FromRegValue;
use winreg::RegKey;

const LOCAL_STORE: &str = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";
const GPO_STORE: &str = r"SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules";
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub const PROFILE_DOMAIN: u8 = 1;
pub const PROFILE_PRIVATE: u8 = 2;
pub const PROFILE_PUBLIC: u8 = 4;
pub const PROFILE_ALL: u8 = 7;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Direction {
    In,
    Out,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Action {
    Allow,
    Block,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Protocol {
    Any,
    Tcp,
    Udp,
    Icmp4,
    Icmp6,
    Other(u8),
}

impl Protocol {
    fn from_number(n: u8) -> Self {
        match n {
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            1 => Protocol::Icmp4,
            58 => Protocol::Icmp6,
            n => Protocol::Other(n),
        }
    }

    pub fn number(self) -> i32 {
        match self {
            Protocol::Any => 256,
            Protocol::Tcp => 6,
            Protocol::Udp => 17,
            Protocol::Icmp4 => 1,
            Protocol::Icmp6 => 58,
            Protocol::Other(n) => n as i32,
        }
    }

    pub fn label(self) -> String {
        match self {
            Protocol::Any => "Any".into(),
            Protocol::Tcp => "TCP".into(),
            Protocol::Udp => "UDP".into(),
            Protocol::Icmp4 => "ICMPv4".into(),
            Protocol::Icmp6 => "ICMPv6".into(),
            Protocol::Other(n) => format!("#{n}"),
        }
    }

    pub fn has_ports(self) -> bool {
        matches!(self, Protocol::Tcp | Protocol::Udp)
    }
}

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum PortSpec {
    Range(u16, u16),
    Keyword(String),
}

impl PortSpec {
    fn parse(s: &str) -> Self {
        let s = s.trim();
        if let Some((a, b)) = s.split_once('-') {
            if let (Ok(a), Ok(b)) = (a.trim().parse(), b.trim().parse()) {
                return PortSpec::Range(a, b);
            }
        }
        match s.parse() {
            Ok(p) => PortSpec::Range(p, p),
            Err(_) => PortSpec::Keyword(s.to_string()),
        }
    }

    pub fn contains(&self, port: u16) -> bool {
        matches!(self, PortSpec::Range(a, b) if *a <= port && port <= *b)
    }

    pub fn label(&self) -> String {
        match self {
            PortSpec::Range(a, b) if a == b => a.to_string(),
            PortSpec::Range(a, b) => format!("{a}-{b}"),
            PortSpec::Keyword(k) => k.clone(),
        }
    }
}

pub fn ports_label(ports: &[PortSpec]) -> String {
    if ports.is_empty() {
        "Any".into()
    } else {
        ports.iter().map(PortSpec::label).collect::<Vec<_>>().join(", ")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Source {
    Local,
    GroupPolicy,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AppState {
    /// Rule is not tied to a program.
    NotSet,
    /// The "System" pseudo-program (kernel).
    System,
    Exists,
    Missing,
}

#[derive(Clone, Debug)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub group: String,
    pub enabled: bool,
    pub action: Action,
    pub direction: Direction,
    pub protocol: Protocol,
    pub local_ports: Vec<PortSpec>,
    pub remote_ports: Vec<PortSpec>,
    pub local_addrs: Vec<String>,
    pub remote_addrs: Vec<String>,
    pub profiles: u8,
    /// Program path as stored (may contain %ENV% variables).
    pub app: Option<String>,
    /// Program path with environment variables expanded.
    pub app_path: Option<String>,
    pub app_state: AppState,
    pub service: Option<String>,
    pub package: Option<String>,
    /// Extra conditions (interfaces, ICMP types, user auth, ...) as a normalized string.
    pub extras: String,
    pub source: Source,
    /// Shipped with Windows / an app manifest (name is a resource reference like `@FirewallAPI.dll,-123`).
    pub builtin: bool,
    /// Lower-cased text used for searching.
    pub haystack: String,
}

impl Rule {
    /// The port that identifies the "service" of this rule: listening port for inbound,
    /// destination port for outbound.
    pub fn service_ports(&self) -> &[PortSpec] {
        match self.direction {
            Direction::In => &self.local_ports,
            Direction::Out => &self.remote_ports,
        }
    }

    pub fn remote_label(&self) -> String {
        if self.remote_addrs.is_empty() {
            "Any".into()
        } else {
            self.remote_addrs.join(", ")
        }
    }

    pub fn program_label(&self) -> String {
        if let Some(p) = &self.app_path {
            p.clone()
        } else if let Some(pkg) = &self.package {
            format!("App package {pkg}")
        } else if let Some(svc) = &self.service {
            format!("Service {svc}")
        } else {
            "Any program".into()
        }
    }

    pub fn can_modify(&self) -> bool {
        self.source == Source::Local
    }
}

pub fn profiles_label(p: u8) -> String {
    if p == PROFILE_ALL {
        return "All".into();
    }
    let mut v = Vec::new();
    if p & PROFILE_DOMAIN != 0 {
        v.push("Domain");
    }
    if p & PROFILE_PRIVATE != 0 {
        v.push("Private");
    }
    if p & PROFILE_PUBLIC != 0 {
        v.push("Public");
    }
    v.join(", ")
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ProfileStatus {
    /// Firewall on/off per profile: domain, private, public.
    pub enabled: [Option<bool>; 3],
    /// Bitmask of the currently active profile(s).
    pub active: u8,
}

pub struct Snapshot {
    pub rules: Vec<Rule>,
    pub status: ProfileStatus,
}

// ---------------------------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------------------------

struct Resolver {
    cache: HashMap<String, String>,
    packages: Option<HashSet<String>>,
}

impl Resolver {
    fn resolve(&mut self, s: &str) -> String {
        if !s.starts_with('@') {
            return s.to_string();
        }
        if let Some(v) = self.cache.get(s) {
            return v.clone();
        }
        let wide: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
        let mut buf = vec![0u16; 1024];
        let out = match unsafe { SHLoadIndirectString(PCWSTR(wide.as_ptr()), &mut buf, None) } {
            Ok(()) => {
                let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
                String::from_utf16_lossy(&buf[..len])
            }
            Err(_) => unresolved_fallback(s),
        };
        self.cache.insert(s.to_string(), out.clone());
        out
    }
}

/// Readable stand-in for a resource string that can't be loaded, e.g. for an uninstalled
/// app package: `@{Microsoft.Foo_1.0_x64__hash?ms-resource://...}` -> `Microsoft.Foo`.
fn unresolved_fallback(s: &str) -> String {
    if let Some(rest) = s.strip_prefix("@{") {
        let end = rest.find(['_', '?', '}']).unwrap_or(rest.len());
        return rest[..end].to_string();
    }
    s.to_string()
}

const PACKAGE_REPOSITORY: &str =
    r"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages";

/// Lower-cased package family names (`Name_PublisherId`) of all installed app packages,
/// or `None` if the repository can't be read.
fn installed_package_families() -> Option<HashSet<String>> {
    let key = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(PACKAGE_REPOSITORY).ok()?;
    let families: HashSet<String> = key
        .enum_keys()
        .filter_map(Result::ok)
        .filter_map(|full| {
            // Full name: Name_Version_Arch_ResourceId_PublisherId
            let name = full.split('_').next()?;
            let publisher = full.rsplit('_').next()?;
            Some(format!("{name}_{publisher}").to_lowercase())
        })
        .collect();
    (!families.is_empty()).then_some(families)
}

pub fn expand_env(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) => {
                let var = &after[..end];
                match std::env::var(var) {
                    Ok(v) if !var.is_empty() => out.push_str(&v),
                    _ => {
                        out.push('%');
                        out.push_str(var);
                        out.push('%');
                    }
                }
                rest = &after[end + 1..];
            }
            None => {
                out.push_str(&rest[start..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

const EXTRA_KEYS: &[&str] = &[
    "IF", "IFType", "LUAuth", "RUAuth", "RUMa", "ICMP4", "ICMP6", "Security", "Security2", "Security2_9",
    "RmtIntrAnet", "TTK", "TTK2_22", "TTK2_27", "TTK2_28", "AuthByPassOut", "SkipVer", "LOM",
];

fn parse_rule(id: &str, data: &str, source: Source, resolver: &mut Resolver) -> Rule {
    let mut fields: Vec<(&str, &str)> = Vec::new();
    for part in data.split('|') {
        if let Some((k, v)) = part.split_once('=') {
            fields.push((k, v));
        }
    }
    let get = |key: &str| fields.iter().find(|(k, _)| *k == key).map(|(_, v)| *v);

    let raw_name = get("Name").unwrap_or(id).to_string();
    let raw_group = get("EmbedCtxt").unwrap_or("").to_string();
    let name = resolver.resolve(&raw_name);
    let description = resolver.resolve(get("Desc").unwrap_or(""));
    let group = resolver.resolve(&raw_group);

    let mut profiles = 0u8;
    let mut local_ports = Vec::new();
    let mut remote_ports = Vec::new();
    let mut local_addrs = Vec::new();
    let mut remote_addrs = Vec::new();
    let mut extras = Vec::new();
    for (k, v) in &fields {
        match *k {
            "Profile" => {
                profiles |= match *v {
                    "Domain" => PROFILE_DOMAIN,
                    "Private" => PROFILE_PRIVATE,
                    "Public" => PROFILE_PUBLIC,
                    _ => 0,
                }
            }
            k if k == "LPort" || k.starts_with("LPort2") => {
                local_ports.extend(v.split(',').filter(|s| !s.is_empty()).map(PortSpec::parse))
            }
            k if k == "RPort" || k.starts_with("RPort2") => {
                remote_ports.extend(v.split(',').filter(|s| !s.is_empty()).map(PortSpec::parse))
            }
            k if k.starts_with("LA4") || k.starts_with("LA6") => local_addrs.push(v.to_string()),
            k if k.starts_with("RA4") || k.starts_with("RA6") => remote_addrs.push(v.to_string()),
            k if EXTRA_KEYS.contains(&k) => extras.push(format!("{k}={v}")),
            _ => {}
        }
    }
    if profiles == 0 {
        profiles = PROFILE_ALL;
    }
    local_ports.sort();
    local_ports.dedup();
    remote_ports.sort();
    remote_ports.dedup();
    // An address list of "*" / "Any" means unrestricted.
    for list in [&mut local_addrs, &mut remote_addrs] {
        list.retain(|a| a != "*" && !a.eq_ignore_ascii_case("any"));
        list.sort_by_key(|a| a.to_lowercase());
        list.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
    }
    extras.sort();

    let app = get("App").filter(|s| !s.is_empty() && *s != "*").map(str::to_string);
    let app_path = app.as_deref().map(expand_env);
    let service = get("Svc").filter(|s| !s.is_empty()).map(str::to_string);
    let package = get("PFN").filter(|s| !s.is_empty()).map(str::to_string);

    let app_state = match (app_path.as_deref(), &package, &resolver.packages) {
        (Some(p), _, _) if p.eq_ignore_ascii_case("system") => AppState::System,
        (Some(p), _, _) if Path::new(p).exists() => AppState::Exists,
        (Some(_), _, _) => AppState::Missing,
        (None, Some(pfn), Some(installed)) if installed.contains(&pfn.to_lowercase()) => AppState::Exists,
        (None, Some(_), Some(_)) => AppState::Missing,
        _ => AppState::NotSet,
    };

    let protocol = get("Protocol")
        .and_then(|p| p.parse::<u16>().ok())
        .map(|n| if n > 255 { Protocol::Any } else { Protocol::from_number(n as u8) })
        .unwrap_or(Protocol::Any);

    let mut rule = Rule {
        id: id.to_string(),
        builtin: raw_name.starts_with('@') || raw_group.starts_with('@'),
        name,
        description,
        group,
        enabled: get("Active").map(|v| v.eq_ignore_ascii_case("TRUE")).unwrap_or(false),
        action: if get("Action") == Some("Block") { Action::Block } else { Action::Allow },
        direction: if get("Dir") == Some("Out") { Direction::Out } else { Direction::In },
        protocol,
        local_ports,
        remote_ports,
        local_addrs,
        remote_addrs,
        profiles,
        app,
        app_path,
        app_state,
        service,
        package,
        extras: extras.join(";"),
        source,
        haystack: String::new(),
    };
    rule.haystack = format!(
        "{} {} {} {} {} {} {} {} {}",
        rule.name,
        rule.description,
        rule.group,
        rule.app_path.as_deref().unwrap_or(""),
        rule.service.as_deref().unwrap_or(""),
        rule.package.as_deref().unwrap_or(""),
        ports_label(&rule.local_ports),
        ports_label(&rule.remote_ports),
        rule.id,
    )
    .to_lowercase();
    rule
}

fn read_store(path: &str, source: Source, resolver: &mut Resolver, out: &mut Vec<Rule>) -> Result<(), String> {
    let key = match RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(path) {
        Ok(k) => k,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("Cannot open {path}: {e}")),
    };
    for item in key.enum_values() {
        let Ok((name, value)) = item else { continue };
        let Ok(data) = String::from_reg_value(&value) else { continue };
        if !data.starts_with('v') {
            continue;
        }
        out.push(parse_rule(&name, &data, source, resolver));
    }
    Ok(())
}

pub fn load() -> Result<Snapshot, String> {
    // Package resource strings (`@{...?ms-resource://...}`) need COM on this thread.
    let _com = ComGuard::new();
    let mut resolver = Resolver { cache: HashMap::new(), packages: installed_package_families() };
    let mut rules = Vec::new();
    read_store(LOCAL_STORE, Source::Local, &mut resolver, &mut rules)?;
    read_store(GPO_STORE, Source::GroupPolicy, &mut resolver, &mut rules)?;
    Ok(Snapshot { rules, status: profile_status() })
}

struct ComGuard(bool);

impl ComGuard {
    fn new() -> Self {
        ComGuard(unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) }.is_ok())
    }
}

impl Drop for ComGuard {
    fn drop(&mut self) {
        if self.0 {
            unsafe { CoUninitialize() };
        }
    }
}

fn profile_status() -> ProfileStatus {
    let _com = ComGuard::new();
    let mut status = ProfileStatus::default();
    let Ok(policy) = (unsafe { CoCreateInstance::<_, INetFwPolicy2>(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER) }) else {
        return status;
    };
    for (i, bit) in [1, 2, 4].into_iter().enumerate() {
        status.enabled[i] = unsafe { policy.get_FirewallEnabled(NET_FW_PROFILE_TYPE2(bit)) }
            .ok()
            .map(|v| v.as_bool());
    }
    status.active = unsafe { policy.CurrentProfileTypes() }.map(|p| (p & 7) as u8).unwrap_or(0);
    status
}

// ---------------------------------------------------------------------------------------------
// Modifying
// ---------------------------------------------------------------------------------------------

#[derive(Default, Debug)]
pub struct OpOutcome {
    pub ok: usize,
    pub errors: Vec<String>,
}

fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// Runs `cmd` (a PowerShell command using `$id`) once per rule ID in a single PowerShell process.
fn run_per_id(ids: &[String], cmd: &str) -> OpOutcome {
    let list = ids.iter().map(|id| ps_quote(id)).collect::<Vec<_>>().join(",\n");
    let script = format!(
        "[Console]::OutputEncoding = [Text.Encoding]::UTF8\n\
         $ErrorActionPreference = 'Stop'\n\
         $ProgressPreference = 'SilentlyContinue'\n\
         foreach ($id in @(\n{list}\n)) {{\n\
           try {{ {cmd}; \"OK|$id\" }} catch {{ \"ERR|$id|$($_.Exception.Message)\" }}\n\
         }}\n"
    );
    let path = std::env::temp_dir().join(format!("fwmgr-{}-{}.ps1", std::process::id(), unique_suffix()));
    let write = std::fs::File::create(&path).and_then(|mut f| {
        // UTF-8 BOM so Windows PowerShell 5.1 reads non-ASCII IDs correctly.
        f.write_all(b"\xEF\xBB\xBF")?;
        f.write_all(script.as_bytes())
    });
    if let Err(e) = write {
        return OpOutcome { ok: 0, errors: vec![format!("Could not write temp script: {e}")] };
    }
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File"])
        .arg(&path)
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    let _ = std::fs::remove_file(&path);

    let mut outcome = OpOutcome::default();
    match output {
        Ok(out) => {
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                if line.starts_with("OK|") {
                    outcome.ok += 1;
                } else if let Some(rest) = line.strip_prefix("ERR|") {
                    outcome.errors.push(rest.replacen('|', ": ", 1));
                }
            }
            if outcome.ok == 0 && outcome.errors.is_empty() {
                let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
                outcome.errors.push(if err.is_empty() { "PowerShell returned no output".into() } else { err });
            }
        }
        Err(e) => outcome.errors.push(format!("Could not start PowerShell: {e}")),
    }
    outcome
}

fn unique_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

pub fn delete_rules(ids: &[String]) -> OpOutcome {
    run_per_id(ids, "Remove-NetFirewallRule -Name $id")
}

pub fn set_enabled(ids: &[String], enabled: bool) -> OpOutcome {
    let flag = if enabled { "True" } else { "False" };
    run_per_id(ids, &format!("Set-NetFirewallRule -Name $id -Enabled {flag}"))
}

#[derive(Clone, Debug)]
pub struct NewRule {
    pub name: String,
    pub description: String,
    pub group: String,
    pub direction: Direction,
    pub action: Action,
    pub protocol: Protocol,
    pub local_ports: String,
    pub remote_ports: String,
    pub remote_addrs: String,
    pub program: String,
    pub service: String,
    pub profiles: u8,
    pub enabled: bool,
}

impl Default for NewRule {
    fn default() -> Self {
        NewRule {
            name: String::new(),
            description: String::new(),
            group: String::new(),
            direction: Direction::In,
            action: Action::Allow,
            protocol: Protocol::Tcp,
            local_ports: String::new(),
            remote_ports: String::new(),
            remote_addrs: String::new(),
            program: String::new(),
            service: String::new(),
            profiles: PROFILE_ALL,
            enabled: true,
        }
    }
}

impl NewRule {
    pub fn from_rule(r: &Rule) -> Self {
        let proto = match r.protocol {
            Protocol::Other(_) => Protocol::Any,
            p => p,
        };
        NewRule {
            name: format!("{} (copy)", r.name),
            description: r.description.clone(),
            group: if r.builtin { String::new() } else { r.group.clone() },
            direction: r.direction,
            action: r.action,
            protocol: proto,
            local_ports: r.local_ports.iter().map(PortSpec::label).collect::<Vec<_>>().join(","),
            remote_ports: r.remote_ports.iter().map(PortSpec::label).collect::<Vec<_>>().join(","),
            remote_addrs: r.remote_addrs.join(","),
            program: r.app.clone().unwrap_or_default(),
            service: r.service.clone().unwrap_or_default(),
            profiles: r.profiles,
            enabled: true,
        }
    }
}

pub fn create_rule(spec: &NewRule) -> Result<(), String> {
    let _com = ComGuard::new();
    let err = |what: &str, e: windows::core::Error| format!("{what}: {}", e.message());
    let clean = |s: &str| s.split(',').map(str::trim).filter(|s| !s.is_empty()).collect::<Vec<_>>().join(",");
    unsafe {
        let policy: INetFwPolicy2 =
            CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER).map_err(|e| err("Open firewall policy", e))?;
        let rule: INetFwRule =
            CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER).map_err(|e| err("Create rule object", e))?;

        rule.SetName(&BSTR::from(spec.name.trim())).map_err(|e| err("Name", e))?;
        if !spec.description.trim().is_empty() {
            rule.SetDescription(&BSTR::from(spec.description.trim())).map_err(|e| err("Description", e))?;
        }
        if !spec.group.trim().is_empty() {
            rule.SetGrouping(&BSTR::from(spec.group.trim())).map_err(|e| err("Group", e))?;
        }
        // Protocol must be set before ports.
        rule.SetProtocol(spec.protocol.number()).map_err(|e| err("Protocol", e))?;
        if spec.protocol.has_ports() {
            let lp = clean(&spec.local_ports);
            if !lp.is_empty() {
                rule.SetLocalPorts(&BSTR::from(lp)).map_err(|e| err("Local ports", e))?;
            }
            let rp = clean(&spec.remote_ports);
            if !rp.is_empty() {
                rule.SetRemotePorts(&BSTR::from(rp)).map_err(|e| err("Remote ports", e))?;
            }
        }
        let ra = clean(&spec.remote_addrs);
        if !ra.is_empty() {
            rule.SetRemoteAddresses(&BSTR::from(ra)).map_err(|e| err("Remote addresses", e))?;
        }
        if !spec.program.trim().is_empty() {
            rule.SetApplicationName(&BSTR::from(spec.program.trim())).map_err(|e| err("Program", e))?;
        }
        if !spec.service.trim().is_empty() {
            rule.SetServiceName(&BSTR::from(spec.service.trim())).map_err(|e| err("Service", e))?;
        }
        rule.SetDirection(NET_FW_RULE_DIRECTION(if spec.direction == Direction::In { 1 } else { 2 }))
            .map_err(|e| err("Direction", e))?;
        rule.SetAction(NET_FW_ACTION(if spec.action == Action::Allow { 1 } else { 0 }))
            .map_err(|e| err("Action", e))?;
        let profiles = if spec.profiles & PROFILE_ALL == PROFILE_ALL { 0x7fff_ffff } else { spec.profiles as i32 };
        rule.SetProfiles(profiles).map_err(|e| err("Profiles", e))?;
        rule.SetEnabled(if spec.enabled { VARIANT_TRUE } else { VARIANT_FALSE }).map_err(|e| err("Enabled", e))?;

        policy.Rules().map_err(|e| err("Open rule list", e))?.Add(&rule).map_err(|e| err("Add rule", e))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Backups & misc
// ---------------------------------------------------------------------------------------------

pub fn data_dir() -> PathBuf {
    let base = std::env::var_os("LOCALAPPDATA").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
    base.join("FirewallManager")
}

pub fn backup_dir() -> PathBuf {
    data_dir().join("backups")
}

/// Exports the full firewall policy (`netsh advfirewall export`). Returns the file path.
pub fn backup() -> Result<PathBuf, String> {
    let dir = backup_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("Cannot create {}: {e}", dir.display()))?;
    let t = unsafe { windows::Win32::System::SystemInformation::GetLocalTime() };
    let path = dir.join(format!(
        "firewall-{:04}{:02}{:02}-{:02}{:02}{:02}.wfw",
        t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond
    ));
    let out = Command::new("netsh")
        .args(["advfirewall", "export"])
        .arg(&path)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("Could not run netsh: {e}"))?;
    if out.status.success() && path.exists() {
        Ok(path)
    } else {
        Err(format!("netsh export failed: {}", String::from_utf8_lossy(&out.stdout).trim()))
    }
}

pub fn is_elevated() -> bool {
    unsafe { windows::Win32::UI::Shell::IsUserAnAdmin().as_bool() }
}

pub fn open_in_explorer(path: &str, select: bool) {
    let mut cmd = Command::new("explorer.exe");
    if select {
        // Explorer wants the quotes around the path only, which `arg` would not produce.
        cmd.raw_arg(format!("/select,\"{path}\""));
    } else {
        cmd.arg(path);
    }
    let _ = cmd.spawn();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(data: &str) -> Rule {
        parse_rule("TEST-ID", data, Source::Local, &mut Resolver { cache: HashMap::new(), packages: None })
    }

    #[test]
    fn parses_registry_rule() {
        let r = parse(
            r"v2.33|Action=Allow|Active=FALSE|Dir=Out|Protocol=6|Profile=Public|Profile=Private|RPort=2869|RPort=5000-5010|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\system32\svchost.exe|Svc=fdphost|Name=Test rule|",
        );
        assert_eq!(r.name, "Test rule");
        assert!(!r.enabled);
        assert_eq!(r.direction, Direction::Out);
        assert_eq!(r.action, Action::Allow);
        assert_eq!(r.protocol, Protocol::Tcp);
        assert_eq!(r.profiles, PROFILE_PUBLIC | PROFILE_PRIVATE);
        assert_eq!(r.remote_ports, vec![PortSpec::Range(2869, 2869), PortSpec::Range(5000, 5010)]);
        assert!(r.local_ports.is_empty());
        assert_eq!(r.remote_addrs, vec!["LocalSubnet".to_string()]);
        assert_eq!(r.service.as_deref(), Some("fdphost"));
        assert!(!r.app_path.as_deref().unwrap().contains('%'));
        assert_eq!(r.app_state, AppState::Exists);
        assert!(!r.builtin);
    }

    #[test]
    fn defaults_and_missing_program() {
        let r = parse(r"v2.10|Action=Block|Active=TRUE|Dir=In|App=C:\definitely\not\here.exe|Name=@FirewallAPI.dll,-1|");
        assert_eq!(r.protocol, Protocol::Any);
        assert_eq!(r.profiles, PROFILE_ALL);
        assert_eq!(r.action, Action::Block);
        assert_eq!(r.app_state, AppState::Missing);
        assert!(r.builtin);
    }

    #[test]
    fn port_spec_parsing() {
        assert_eq!(PortSpec::parse("80"), PortSpec::Range(80, 80));
        assert_eq!(PortSpec::parse("100-200"), PortSpec::Range(100, 200));
        assert_eq!(PortSpec::parse("RPC-EPMap"), PortSpec::Keyword("RPC-EPMap".into()));
        assert!(PortSpec::Range(100, 200).contains(150));
    }

    #[test]
    fn env_expansion() {
        std::env::set_var("FWMGR_TEST_VAR", "X");
        assert_eq!(expand_env("a%FWMGR_TEST_VAR%b"), "aXb");
        assert_eq!(expand_env(r"%NOPE_NOT_SET%\x"), r"%NOPE_NOT_SET%\x");
        assert_eq!(expand_env("50%"), "50%");
    }

    #[test]
    #[ignore = "reads the real firewall store; run with --ignored --nocapture"]
    fn load_real_rules() {
        let snap = load().expect("load");
        let a = crate::analysis::analyze(&snap.rules);
        println!("rules: {}  status: {:?}", snap.rules.len(), snap.status);
        for kind in crate::analysis::IssueKind::ALL {
            let n = a.issues.iter().filter(|v| v.iter().any(|x| x.kind == kind)).count();
            println!("{:<28} {n}", kind.title());
        }
        for (i, list) in a.issues.iter().enumerate() {
            for x in list.iter().filter(|x| x.severity >= crate::analysis::Severity::Medium).take(1) {
                println!("  [{:?}] {} -> {}", x.severity, snap.rules[i].name, x.detail);
            }
        }
        assert!(!snap.rules.is_empty());
    }
}
