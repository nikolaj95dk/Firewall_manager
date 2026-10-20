//! Well-known ports worth a second look when they are open inbound.

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Risk {
    Notable,
    Sensitive,
    Critical,
}

pub struct KnownPort {
    pub port: u16,
    pub tcp: bool,
    pub udp: bool,
    pub name: &'static str,
    pub why: &'static str,
    pub risk: Risk,
}

const fn p(port: u16, tcp: bool, udp: bool, name: &'static str, why: &'static str, risk: Risk) -> KnownPort {
    KnownPort { port, tcp, udp, name, why, risk }
}

use Risk::*;

pub const KNOWN_PORTS: &[KnownPort] = &[
    p(20, true, false, "FTP data", "Unencrypted file transfer", Sensitive),
    p(21, true, false, "FTP", "Unencrypted logins and file transfer", Critical),
    p(22, true, false, "SSH", "Remote shell access - keep only if you SSH into this PC", Sensitive),
    p(23, true, false, "Telnet", "Unencrypted remote shell, should never be open", Critical),
    p(25, true, false, "SMTP", "Mail server, rarely needed on a desktop", Sensitive),
    p(53, true, true, "DNS", "DNS server, rarely needed on a desktop", Sensitive),
    p(69, false, true, "TFTP", "Unauthenticated file transfer", Critical),
    p(80, true, false, "HTTP", "Web server", Notable),
    p(110, true, false, "POP3", "Mail server", Sensitive),
    p(111, true, true, "RPCbind", "Remote procedure call mapper", Sensitive),
    p(135, true, false, "MS-RPC", "Windows RPC endpoint mapper, common attack target", Critical),
    p(137, false, true, "NetBIOS name", "Legacy Windows networking, leaks host info", Critical),
    p(138, false, true, "NetBIOS datagram", "Legacy Windows networking", Critical),
    p(139, true, false, "NetBIOS session", "Legacy file sharing (SMBv1 era)", Critical),
    p(143, true, false, "IMAP", "Mail server", Sensitive),
    p(161, false, true, "SNMP", "Device management, often weak community strings", Sensitive),
    p(389, true, true, "LDAP", "Directory service", Sensitive),
    p(443, true, false, "HTTPS", "Web server", Notable),
    p(445, true, false, "SMB", "File/printer sharing, frequent worm and ransomware target", Critical),
    p(1433, true, false, "SQL Server", "Database exposed to the network", Critical),
    p(1434, false, true, "SQL Browser", "SQL Server discovery", Sensitive),
    p(1521, true, false, "Oracle DB", "Database exposed to the network", Critical),
    p(1723, true, false, "PPTP", "Legacy VPN with broken crypto", Sensitive),
    p(1900, false, true, "SSDP / UPnP", "Device discovery, abused for amplification", Sensitive),
    p(2049, true, true, "NFS", "Network file system", Sensitive),
    p(2375, true, false, "Docker API", "Unencrypted Docker daemon = full control of the host", Critical),
    p(2376, true, false, "Docker API (TLS)", "Docker daemon remote control", Sensitive),
    p(3000, true, false, "Dev server", "Typical development web server", Notable),
    p(3306, true, false, "MySQL", "Database exposed to the network", Critical),
    p(3389, true, true, "RDP", "Remote Desktop, top brute-force target", Critical),
    p(5000, true, false, "Dev server / UPnP", "Development server or UPnP", Notable),
    p(5353, false, true, "mDNS", "Local network discovery", Notable),
    p(5357, true, false, "WSDAPI", "Network device discovery", Notable),
    p(5432, true, false, "PostgreSQL", "Database exposed to the network", Critical),
    p(5800, true, false, "VNC (web)", "Remote desktop", Critical),
    p(5900, true, false, "VNC", "Remote desktop, often weak passwords", Critical),
    p(5985, true, false, "WinRM HTTP", "Remote PowerShell management", Critical),
    p(5986, true, false, "WinRM HTTPS", "Remote PowerShell management", Sensitive),
    p(6379, true, false, "Redis", "In-memory database with no auth by default", Critical),
    p(8080, true, false, "HTTP alt", "Proxy or development web server", Notable),
    p(8443, true, false, "HTTPS alt", "Alternate web server", Notable),
    p(9200, true, false, "Elasticsearch", "Search database with no auth by default", Critical),
    p(11211, true, true, "Memcached", "Cache server, abused for amplification", Critical),
    p(27017, true, false, "MongoDB", "Database exposed to the network", Critical),
];

pub fn lookup(port: u16) -> Option<&'static KnownPort> {
    KNOWN_PORTS.iter().find(|k| k.port == port)
}
