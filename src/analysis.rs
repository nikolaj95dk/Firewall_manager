//! Finds rules worth a second look: dead programs, duplicates, rules made redundant by a
//! broader rule, exposed sensitive ports, wide-open inbound rules, etc.

use std::collections::HashMap;

use crate::firewall::{Action, AppState, Direction, PortSpec, Protocol, Rule, Source};
use crate::ports::{self, KnownPort, Risk, KNOWN_PORTS};

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "Info",
            Severity::Low => "Low",
            Severity::Medium => "Medium",
            Severity::High => "High",
        }
    }

    fn lower(self) -> Self {
        match self {
            Severity::High => Severity::Medium,
            Severity::Medium => Severity::Low,
            _ => Severity::Info,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum IssueKind {
    MissingProgram,
    Duplicate,
    Covered,
    ExposedPort,
    BroadInbound,
    SuspiciousPath,
    Disabled,
}

impl IssueKind {
    pub const ALL: [IssueKind; 7] = [
        IssueKind::ExposedPort,
        IssueKind::BroadInbound,
        IssueKind::MissingProgram,
        IssueKind::Duplicate,
        IssueKind::Covered,
        IssueKind::SuspiciousPath,
        IssueKind::Disabled,
    ];

    pub fn title(self) -> &'static str {
        match self {
            IssueKind::MissingProgram => "Program missing",
            IssueKind::Duplicate => "Duplicate",
            IssueKind::Covered => "Covered by broader rule",
            IssueKind::ExposedPort => "Sensitive port open",
            IssueKind::BroadInbound => "Wide-open inbound",
            IssueKind::SuspiciousPath => "Program in Temp/Downloads",
            IssueKind::Disabled => "Disabled custom rule",
        }
    }

    pub fn short(self) -> &'static str {
        match self {
            IssueKind::MissingProgram => "Missing",
            IssueKind::Duplicate => "Duplicate",
            IssueKind::Covered => "Covered",
            IssueKind::ExposedPort => "Port",
            IssueKind::BroadInbound => "Wide open",
            IssueKind::SuspiciousPath => "Temp path",
            IssueKind::Disabled => "Disabled",
        }
    }

    pub fn explanation(self) -> &'static str {
        match self {
            IssueKind::MissingProgram => {
                "The program (or Store app package) these rules point to no longer exists (uninstalled, moved, or \
                 an old version folder). The rules do nothing and are safe to remove."
            }
            IssueKind::Duplicate => {
                "Rules identical in every condition to another rule. One copy is kept unflagged; the flagged \
                 copies are redundant and safe to remove."
            }
            IssueKind::Covered => {
                "Rules that never change anything because another enabled rule with the same action already \
                 matches a superset of their traffic (e.g. same program, all ports)."
            }
            IssueKind::ExposedPort => {
                "Enabled inbound allow rules that open well-known sensitive ports (RDP, SMB, databases, ...). \
                 Make sure you still need them, and limit the remote addresses if you can."
            }
            IssueKind::BroadInbound => {
                "Enabled inbound allow rules not tied to any program or service and covering all ports. These \
                 effectively punch a hole through the firewall."
            }
            IssueKind::SuspiciousPath => {
                "Rules for programs living in Temp or Downloads folders - usually installers or one-off tools \
                 that were allowed once and forgotten."
            }
            IssueKind::Disabled => {
                "Non built-in rules that are switched off. They have no effect; delete them if you don't plan \
                 to turn them back on."
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct Issue {
    pub kind: IssueKind,
    pub severity: Severity,
    pub detail: String,
    /// Another rule this issue refers to (the kept duplicate / the broader rule).
    pub related: Option<usize>,
}

pub struct PortEntry {
    pub spec: PortSpec,
    pub protocol: Protocol,
    pub rules: Vec<usize>,
    pub inbound_allow: usize,
    pub known: Option<&'static KnownPort>,
}

pub struct ProgramEntry {
    pub key: String,
    pub label: String,
    pub state: AppState,
    pub rules: Vec<usize>,
    pub inbound_allow: usize,
}

#[derive(Default)]
pub struct Analysis {
    pub issues: Vec<Vec<Issue>>,
    pub ports: Vec<PortEntry>,
    pub programs: Vec<ProgramEntry>,
}

pub fn program_key(r: &Rule) -> String {
    if let Some(p) = &r.app_path {
        p.to_lowercase()
    } else if let Some(pkg) = &r.package {
        format!("pkg:{}", pkg.to_lowercase())
    } else if let Some(svc) = &r.service {
        format!("svc:{}", svc.to_lowercase())
    } else {
        String::new()
    }
}

fn fingerprint(r: &Rule) -> String {
    format!(
        "{:?}|{:?}|{:?}|{:?}|{:?}|{}|{}|{}|{}|{}|{}|{}",
        r.direction,
        r.action,
        r.protocol,
        r.local_ports,
        r.remote_ports,
        r.local_addrs.join(",").to_lowercase(),
        r.remote_addrs.join(",").to_lowercase(),
        r.profiles,
        r.app_path.as_deref().unwrap_or("").to_lowercase(),
        r.service.as_deref().unwrap_or("").to_lowercase(),
        r.package.as_deref().unwrap_or("").to_lowercase(),
        r.extras,
    )
}

fn ports_cover(outer: &[PortSpec], inner: &[PortSpec]) -> bool {
    if outer.is_empty() {
        return true;
    }
    if inner.is_empty() {
        return false;
    }
    inner.iter().all(|i| {
        outer.iter().any(|o| match (o, i) {
            (PortSpec::Range(a, b), PortSpec::Range(c, d)) => a <= c && d <= b,
            (PortSpec::Keyword(a), PortSpec::Keyword(b)) => a.eq_ignore_ascii_case(b),
            _ => false,
        })
    })
}

fn addrs_cover(outer: &[String], inner: &[String]) -> bool {
    outer.is_empty()
        || (outer.len() == inner.len() && outer.iter().zip(inner).all(|(a, b)| a.eq_ignore_ascii_case(b)))
}

fn opt_cover(outer: &Option<String>, inner: &Option<String>) -> bool {
    match (outer, inner) {
        (None, _) => true,
        (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
        (Some(_), None) => false,
    }
}

/// True when every packet `inner` matches is also matched by `outer`.
fn covers(outer: &Rule, inner: &Rule) -> bool {
    outer.direction == inner.direction
        && outer.action == inner.action
        && (outer.protocol == Protocol::Any || outer.protocol == inner.protocol)
        && outer.profiles & inner.profiles == inner.profiles
        && (outer.extras.is_empty() || outer.extras == inner.extras)
        && opt_cover(&outer.app_path, &inner.app_path)
        && opt_cover(&outer.service, &inner.service)
        && opt_cover(&outer.package, &inner.package)
        && (outer.protocol == Protocol::Any || ports_cover(&outer.local_ports, &inner.local_ports))
        && (outer.protocol == Protocol::Any || ports_cover(&outer.remote_ports, &inner.remote_ports))
        && addrs_cover(&outer.local_addrs, &inner.local_addrs)
        && addrs_cover(&outer.remote_addrs, &inner.remote_addrs)
}

fn is_suspicious_path(p: &str) -> bool {
    let p = p.to_lowercase();
    p.contains("\\temp\\") || p.contains("\\tmp\\") || p.contains("\\downloads\\") || p.contains("\\temporary internet files\\")
}

fn risk_severity(risk: Risk) -> Severity {
    match risk {
        Risk::Critical => Severity::High,
        Risk::Sensitive => Severity::Medium,
        Risk::Notable => Severity::Low,
    }
}

fn protocol_matches(proto: Protocol, k: &KnownPort) -> bool {
    match proto {
        Protocol::Tcp => k.tcp,
        Protocol::Udp => k.udp,
        _ => false,
    }
}

pub fn analyze(rules: &[Rule]) -> Analysis {
    let mut issues: Vec<Vec<Issue>> = vec![Vec::new(); rules.len()];

    // --- Per-rule checks -------------------------------------------------------------------
    for (i, r) in rules.iter().enumerate() {
        if r.app_state == AppState::Missing {
            issues[i].push(Issue {
                kind: IssueKind::MissingProgram,
                severity: Severity::Medium,
                detail: match (&r.app_path, &r.package) {
                    (Some(p), _) => format!("Not found: {p}"),
                    (None, Some(pkg)) => format!("App package not installed: {pkg}"),
                    _ => "Program not found".into(),
                },
                related: None,
            });
        }
        if let Some(p) = &r.app_path {
            if is_suspicious_path(p) {
                issues[i].push(Issue {
                    kind: IssueKind::SuspiciousPath,
                    severity: Severity::Medium,
                    detail: "Program lives in a Temp or Downloads folder".into(),
                    related: None,
                });
            }
        }
        if !r.enabled && !r.builtin && r.source == Source::Local {
            issues[i].push(Issue {
                kind: IssueKind::Disabled,
                severity: Severity::Info,
                detail: "Rule is switched off and has no effect".into(),
                related: None,
            });
        }

        let inbound_allow = r.enabled && r.direction == Direction::In && r.action == Action::Allow;
        if !inbound_allow {
            continue;
        }
        let restricted = !r.remote_addrs.is_empty();
        let scope = if restricted { format!("from {}", r.remote_label()) } else { "from any address".into() };

        if r.app.is_none()
            && r.service.is_none()
            && r.package.is_none()
            && r.local_ports.is_empty()
            && matches!(r.protocol, Protocol::Any | Protocol::Tcp | Protocol::Udp)
        {
            let sev = if restricted { Severity::Medium } else { Severity::High };
            issues[i].push(Issue {
                kind: IssueKind::BroadInbound,
                severity: sev,
                detail: match r.protocol {
                    Protocol::Any => format!("All ports and protocols open {scope}, for any program"),
                    p => format!("All {} ports open {scope}, for any program", p.label()),
                },
                related: None,
            });
        }

        if r.protocol.has_ports() {
            let mut hits: Vec<&KnownPort> = Vec::new();
            let mut wide = None;
            for spec in &r.local_ports {
                if let PortSpec::Range(a, b) = spec {
                    if b - a > 100 {
                        wide = Some((*a, *b));
                        continue;
                    }
                    for k in KNOWN_PORTS {
                        if spec.contains(k.port) && protocol_matches(r.protocol, k) && !hits.iter().any(|h| h.port == k.port) {
                            hits.push(k);
                        }
                    }
                }
            }
            if !hits.is_empty() || wide.is_some() {
                let mut sev = hits.iter().map(|k| risk_severity(k.risk)).max().unwrap_or(Severity::Low);
                let mut parts: Vec<String> = hits.iter().map(|k| format!("{} {}", k.port, k.name)).collect();
                if let Some((a, b)) = wide {
                    parts.push(format!("wide range {a}-{b}"));
                    sev = sev.max(Severity::Medium);
                }
                if restricted {
                    sev = sev.lower();
                }
                issues[i].push(Issue {
                    kind: IssueKind::ExposedPort,
                    severity: sev,
                    detail: format!("Opens {} {scope}", parts.join(", ")),
                    related: None,
                });
            }
        }
    }

    // --- Duplicates -------------------------------------------------------------------------
    let mut groups: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, r) in rules.iter().enumerate() {
        // Built-in rules of different Windows features often define identical traffic; each is
        // still needed for its own feature's on/off switch, so only compare within a group.
        let key = if r.builtin { format!("{}|{}", fingerprint(r), r.group) } else { fingerprint(r) };
        groups.entry(key).or_default().push(i);
    }
    for members in groups.values().filter(|m| m.len() > 1) {
        // Keep the best copy: enabled first, then modifiable, then the one with a description.
        let keep = *members
            .iter()
            .max_by_key(|&&i| (rules[i].enabled, rules[i].can_modify(), rules[i].builtin, !rules[i].description.is_empty()))
            .unwrap();
        for &i in members.iter().filter(|&&i| i != keep) {
            issues[i].push(Issue {
                kind: IssueKind::Duplicate,
                severity: Severity::Low,
                detail: format!("Same as \"{}\" ({} copies in total)", rules[keep].name, members.len()),
                related: Some(keep),
            });
        }
    }

    // --- Covered by a broader rule ------------------------------------------------------------
    let mut by_bucket: HashMap<(Direction, Action), Vec<usize>> = HashMap::new();
    for (i, r) in rules.iter().enumerate() {
        if r.enabled {
            by_bucket.entry((r.direction, r.action)).or_default().push(i);
        }
    }
    for (i, r) in rules.iter().enumerate() {
        if issues[i].iter().any(|x| x.kind == IssueKind::Duplicate) {
            continue;
        }
        let Some(candidates) = by_bucket.get(&(r.direction, r.action)) else { continue };
        let inner_fp = fingerprint(r);
        let broader = candidates
            .iter()
            .copied()
            .filter(|&o| o != i && covers(&rules[o], r) && fingerprint(&rules[o]) != inner_fp)
            // Same reasoning as duplicates: a built-in rule is only redundant within its own feature.
            .filter(|&o| !r.builtin || rules[o].group == r.group)
            // Prefer the narrowest covering rule (one tied to a program) as the explanation.
            .min_by_key(|&o| (rules[o].app_path.is_none(), rules[o].local_ports.is_empty()));
        if let Some(o) = broader {
            issues[i].push(Issue {
                kind: IssueKind::Covered,
                severity: Severity::Low,
                detail: format!("Already handled by \"{}\"", rules[o].name),
                related: Some(o),
            });
        }
    }

    for list in issues.iter_mut() {
        list.sort_by(|a, b| b.severity.cmp(&a.severity));
    }

    // --- Port overview ------------------------------------------------------------------------
    let mut port_map: HashMap<(Protocol, PortSpec), Vec<usize>> = HashMap::new();
    for (i, r) in rules.iter().enumerate() {
        for spec in r.service_ports() {
            port_map.entry((r.protocol, spec.clone())).or_default().push(i);
        }
    }
    let mut ports: Vec<PortEntry> = port_map
        .into_iter()
        .map(|((protocol, spec), idx)| {
            let known = match &spec {
                PortSpec::Range(a, b) if a == b => ports::lookup(*a).filter(|k| protocol_matches(protocol, k)),
                _ => None,
            };
            let inbound_allow = idx
                .iter()
                .filter(|&&i| rules[i].enabled && rules[i].direction == Direction::In && rules[i].action == Action::Allow)
                .count();
            PortEntry { spec, protocol, rules: idx, inbound_allow, known }
        })
        .collect();
    ports.sort_by(|a, b| a.spec.cmp(&b.spec).then(a.protocol.number().cmp(&b.protocol.number())));

    // --- Programs -------------------------------------------------------------------------------
    let mut prog_map: HashMap<String, ProgramEntry> = HashMap::new();
    for (i, r) in rules.iter().enumerate() {
        let key = program_key(r);
        let entry = prog_map.entry(key.clone()).or_insert_with(|| ProgramEntry {
            label: if key.is_empty() { "Any program (port / address based rules)".into() } else { r.program_label() },
            key,
            state: r.app_state,
            rules: Vec::new(),
            inbound_allow: 0,
        });
        entry.rules.push(i);
        if r.enabled && r.direction == Direction::In && r.action == Action::Allow {
            entry.inbound_allow += 1;
        }
    }
    let mut programs: Vec<ProgramEntry> = prog_map.into_values().collect();
    programs.sort_by(|a, b| {
        (b.state == AppState::Missing)
            .cmp(&(a.state == AppState::Missing))
            .then(b.rules.len().cmp(&a.rules.len()))
            .then(a.label.cmp(&b.label))
    });

    Analysis { issues, ports, programs }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::PROFILE_ALL;

    fn rule(name: &str, f: impl FnOnce(&mut Rule)) -> Rule {
        let mut r = Rule {
            id: name.into(),
            name: name.into(),
            description: String::new(),
            group: String::new(),
            enabled: true,
            action: Action::Allow,
            direction: Direction::In,
            protocol: Protocol::Tcp,
            local_ports: vec![],
            remote_ports: vec![],
            local_addrs: vec![],
            remote_addrs: vec![],
            profiles: PROFILE_ALL,
            app: None,
            app_path: None,
            app_state: AppState::NotSet,
            service: None,
            package: None,
            extras: String::new(),
            source: Source::Local,
            builtin: false,
            haystack: String::new(),
        };
        f(&mut r);
        r
    }

    fn kinds(a: &Analysis, i: usize) -> Vec<IssueKind> {
        a.issues[i].iter().map(|x| x.kind).collect()
    }

    #[test]
    fn duplicates_keep_one() {
        let rules = vec![
            rule("a", |r| r.local_ports = vec![PortSpec::Range(8000, 8000)]),
            rule("b", |r| r.local_ports = vec![PortSpec::Range(8000, 8000)]),
            rule("c", |r| r.local_ports = vec![PortSpec::Range(8001, 8001)]),
        ];
        let a = analyze(&rules);
        let dup: Vec<usize> = (0..3).filter(|&i| kinds(&a, i).contains(&IssueKind::Duplicate)).collect();
        assert_eq!(dup.len(), 1);
        assert!(!kinds(&a, 2).contains(&IssueKind::Duplicate));
    }

    #[test]
    fn covered_by_program_wide_rule() {
        let app = |r: &mut Rule| {
            r.app_path = Some(r"C:\x\app.exe".into());
            r.app = r.app_path.clone();
        };
        let rules = vec![
            rule("all ports", app),
            rule("port 80", |r| {
                app(r);
                r.local_ports = vec![PortSpec::Range(80, 80)];
            }),
            rule("other app", |r| r.local_ports = vec![PortSpec::Range(80, 80)]),
        ];
        let a = analyze(&rules);
        assert!(kinds(&a, 1).contains(&IssueKind::Covered));
        assert!(!kinds(&a, 0).contains(&IssueKind::Covered));
        // A rule for any program is not covered by a program-specific one.
        assert!(!kinds(&a, 2).contains(&IssueKind::Covered));
    }

    #[test]
    fn disabled_rule_covers_nothing() {
        let rules = vec![
            rule("wide", |r| r.enabled = false),
            rule("narrow", |r| r.local_ports = vec![PortSpec::Range(80, 80)]),
        ];
        let a = analyze(&rules);
        assert!(!kinds(&a, 1).contains(&IssueKind::Covered));
    }

    #[test]
    fn exposed_and_broad() {
        let rules = vec![
            rule("rdp", |r| r.local_ports = vec![PortSpec::Range(3389, 3389)]),
            rule("rdp lan", |r| {
                r.local_ports = vec![PortSpec::Range(3389, 3389)];
                r.remote_addrs = vec!["LocalSubnet".into()];
            }),
            rule("open", |r| r.protocol = Protocol::Any),
            rule("rdp out", |r| {
                r.direction = Direction::Out;
                r.local_ports = vec![PortSpec::Range(3389, 3389)];
            }),
        ];
        let a = analyze(&rules);
        let sev = |i: usize| a.issues[i].iter().find(|x| x.kind == IssueKind::ExposedPort).map(|x| x.severity);
        assert_eq!(sev(0), Some(Severity::High));
        assert_eq!(sev(1), Some(Severity::Medium));
        assert_eq!(sev(3), None);
        assert!(kinds(&a, 2).contains(&IssueKind::BroadInbound));
    }
}
