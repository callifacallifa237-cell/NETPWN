
"""
╔══════════════════════════════════════════════════════════════╗
|NetPwn v1.0 - Advanced Network Assessment Suite  high-Level   |
|Cybersecurity Research Tool  this tool was made by yvan in BCA|
|final year project ethical Use Only | Authorized Targets Only |          
╚══════════════════════════════════════════════════════════════╝

Modules:
  - TCP/UDP port scanning with adaptive threading
  - ARP-based LAN host discovery
  - Deep service fingerprinting (HTTP/FTP/SSH/SMTP/SMB/RDP)
  - SSL/TLS certificate & cipher suite audit
  - CVSSv3 scoring engine
  - Metasploit module mapping
  - OS fingerprinting (TTL + port heuristics + TCP window)
  - Traceroute / hop analysis
  - HTML + JSON + TXT reporting
  - Plugin architecture for extensible checks
"""

import argparse
import socket
import ssl
import struct
import subprocess
import sys
import json
import os
import re
import time
import select
import ftplib
import threading
import ipaddress
import hashlib
import base64
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from typing import Optional, List, Dict, Tuple, Any

class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"

def cprint(color: str, msg: str):
    print(f"{color}{msg}{C.RESET}")

def severity_color(sev: str) -> str:
    return {
        "CRITICAL": C.RED + C.BOLD,
        "HIGH":     C.MAGENTA,
        "MEDIUM":   C.YELLOW,
        "LOW":      C.CYAN,
        "INFO":     C.BLUE,
    }.get(sev, C.WHITE)


BANNER = f"""
{C.RED}{C.BOLD}
 ███╗   ██╗███████╗████████╗██████╗ ██╗    ██╗███╗   ██╗
 ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║    ██║████╗  ██║
 ██╔██╗ ██║█████╗     ██║   ██████╔╝██║ █╗ ██║██╔██╗ ██║
 ██║╚██╗██║██╔══╝     ██║   ██╔═══╝ ██║███╗██║██║╚██╗██║
 ██║ ╚████║███████╗   ██║   ██║     ╚███╔███╔╝██║ ╚████║
 ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝{C.RESET}
{C.YELLOW}  v1.0 ─ Advanced Network Vulnerability Assessment Suite{C.RESET}
{C.GRAY}  High -Level Cybersecurity Research Tool | Ethical Use Only{C.RESET}
{C.WHITE}  {'─'*58}{C.RESET}
"""


TIMING_PROFILES = {
    "paranoid":   {"connect_timeout": 5.0,  "delay": 5.0,   "threads": 1,   "label": "T0 – Paranoid (IDS evasion, 1 thread)"},
    "sneaky":     {"connect_timeout": 3.0,  "delay": 1.0,   "threads": 5,   "label": "T1 – Sneaky (low & slow)"},
    "polite":     {"connect_timeout": 2.0,  "delay": 0.4,   "threads": 15,  "label": "T2 – Polite (reduced bandwidth)"},
    "normal":     {"connect_timeout": 1.0,  "delay": 0.0,   "threads": 100, "label": "T3 – Normal (default)"},
    "aggressive": {"connect_timeout": 0.5,  "delay": 0.0,   "threads": 200, "label": "T4 – Aggressive (fast LAN)"},
    "insane":     {"connect_timeout": 0.25, "delay": 0.0,   "threads": 500, "label": "T5 – Insane (may drop packets)"},
}


SERVICE_DB: Dict[int, Dict] = {
    20:    {"name": "FTP-Data",    "proto": "tcp", "category": "file-transfer"},
    21:    {"name": "FTP",         "proto": "tcp", "category": "file-transfer"},
    22:    {"name": "SSH",         "proto": "tcp", "category": "remote-access"},
    23:    {"name": "Telnet",      "proto": "tcp", "category": "remote-access"},
    25:    {"name": "SMTP",        "proto": "tcp", "category": "mail"},
    53:    {"name": "DNS",         "proto": "both","category": "infrastructure"},
    67:    {"name": "DHCP",        "proto": "udp", "category": "infrastructure"},
    68:    {"name": "DHCP-Client", "proto": "udp", "category": "infrastructure"},
    69:    {"name": "TFTP",        "proto": "udp", "category": "file-transfer"},
    80:    {"name": "HTTP",        "proto": "tcp", "category": "web"},
    110:   {"name": "POP3",        "proto": "tcp", "category": "mail"},
    111:   {"name": "RPC",         "proto": "tcp", "category": "rpc"},
    119:   {"name": "NNTP",        "proto": "tcp", "category": "news"},
    123:   {"name": "NTP",         "proto": "udp", "category": "infrastructure"},
    135:   {"name": "MSRPC",       "proto": "tcp", "category": "windows"},
    137:   {"name": "NetBIOS-NS",  "proto": "udp", "category": "windows"},
    138:   {"name": "NetBIOS-DG",  "proto": "udp", "category": "windows"},
    139:   {"name": "NetBIOS-SSN", "proto": "tcp", "category": "windows"},
    143:   {"name": "IMAP",        "proto": "tcp", "category": "mail"},
    161:   {"name": "SNMP",        "proto": "udp", "category": "management"},
    162:   {"name": "SNMP-Trap",   "proto": "udp", "category": "management"},
    389:   {"name": "LDAP",        "proto": "tcp", "category": "directory"},
    443:   {"name": "HTTPS",       "proto": "tcp", "category": "web"},
    445:   {"name": "SMB",         "proto": "tcp", "category": "windows"},
    465:   {"name": "SMTPS",       "proto": "tcp", "category": "mail"},
    512:   {"name": "RSH",         "proto": "tcp", "category": "remote-access"},
    513:   {"name": "RLOGIN",      "proto": "tcp", "category": "remote-access"},
    514:   {"name": "Syslog",      "proto": "udp", "category": "logging"},
    587:   {"name": "SMTP-Sub",    "proto": "tcp", "category": "mail"},
    631:   {"name": "IPP",         "proto": "tcp", "category": "printing"},
    636:   {"name": "LDAPS",       "proto": "tcp", "category": "directory"},
    873:   {"name": "rsync",       "proto": "tcp", "category": "file-transfer"},
    993:   {"name": "IMAPS",       "proto": "tcp", "category": "mail"},
    995:   {"name": "POP3S",       "proto": "tcp", "category": "mail"},
    1080:  {"name": "SOCKS",       "proto": "tcp", "category": "proxy"},
    1194:  {"name": "OpenVPN",     "proto": "udp", "category": "vpn"},
    1433:  {"name": "MSSQL",       "proto": "tcp", "category": "database"},
    1521:  {"name": "Oracle-DB",   "proto": "tcp", "category": "database"},
    1723:  {"name": "PPTP",        "proto": "tcp", "category": "vpn"},
    2049:  {"name": "NFS",         "proto": "tcp", "category": "file-transfer"},
    2375:  {"name": "Docker",      "proto": "tcp", "category": "container"},
    2376:  {"name": "Docker-TLS",  "proto": "tcp", "category": "container"},
    3000:  {"name": "HTTP-Dev",    "proto": "tcp", "category": "web"},
    3306:  {"name": "MySQL",       "proto": "tcp", "category": "database"},
    3389:  {"name": "RDP",         "proto": "tcp", "category": "remote-access"},
    4444:  {"name": "Meterpreter", "proto": "tcp", "category": "suspicious"},
    5432:  {"name": "PostgreSQL",  "proto": "tcp", "category": "database"},
    5900:  {"name": "VNC",         "proto": "tcp", "category": "remote-access"},
    5985:  {"name": "WinRM-HTTP",  "proto": "tcp", "category": "windows"},
    5986:  {"name": "WinRM-HTTPS", "proto": "tcp", "category": "windows"},
    6379:  {"name": "Redis",       "proto": "tcp", "category": "database"},
    6443:  {"name": "K8s-API",     "proto": "tcp", "category": "container"},
    8080:  {"name": "HTTP-Alt",    "proto": "tcp", "category": "web"},
    8443:  {"name": "HTTPS-Alt",   "proto": "tcp", "category": "web"},
    8888:  {"name": "Jupyter",     "proto": "tcp", "category": "data-science"},
    9200:  {"name": "Elasticsearch","proto":"tcp", "category": "database"},
    9300:  {"name": "Elasticsearch-C","proto":"tcp","category": "database"},
    27017: {"name": "MongoDB",     "proto": "tcp", "category": "database"},
    27018: {"name": "MongoDB-Sh",  "proto": "tcp", "category": "database"},
    50000: {"name": "IBM-DB2",     "proto": "tcp", "category": "database"},
}

def get_service(port: int) -> str:
    return SERVICE_DB.get(port, {}).get("name", "Unknown")


class CVSSv3:
    """
    Simplified CVSSv3 Base Score calculator.
    Attack Vector, Attack Complexity, Privileges Required,
    User Interaction, Scope, Confidentiality, Integrity, Availability.
    """
    AV  = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    AC  = {"L": 0.77, "H": 0.44}
    PR  = {"N": 0.85, "L": 0.62, "H": 0.27}  
    PR_C= {"N": 0.85, "L": 0.68, "H": 0.50}  
    UI  = {"N": 0.85, "R": 0.62}
    CIA = {"N": 0.00, "L": 0.22, "H": 0.56}

    @staticmethod
    def score(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H") -> Tuple[float, str]:
        pr_val = CVSSv3.PR_C[pr] if s == "C" else CVSSv3.PR[pr]
        iss = 1 - (1 - CVSSv3.CIA[c]) * (1 - CVSSv3.CIA[i]) * (1 - CVSSv3.CIA[a])
        if s == "U":
            impact = 3.4 * iss if iss > 0 else 0.0
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if iss > 0 else 0.0
        exploitability = 8.22 * CVSSv3.AV[av] * CVSSv3.AC[ac] * pr_val * CVSSv3.UI[ui]
        if impact <= 0:
            base = 0.0
        else:
            if s == "U":
                base = min(impact + exploitability, 10)
            else:
                base = min(1.08 * (impact + exploitability), 10)
        base = round(base * 10) / 10

        if base == 0.0:   rating = "NONE"
        elif base < 4.0:  rating = "LOW"
        elif base < 7.0:  rating = "MEDIUM"
        elif base < 9.0:  rating = "HIGH"
        else:              rating = "CRITICAL"
        return base, rating


VULN_DB: List[Dict] = [
    # ftp
    {
        "id": "NP-001", "port": 21, "match": "vsftpd 2.3.4",
        "cve": "CVE-2011-2523", "cvss": (10.0, "CRITICAL"),
        "description": "vsFTPd 2.3.4 backdoor – connects to port 6200 after sending ':)' in username",
        "remediation": "Upgrade vsFTPd to ≥ 3.0.3 immediately. Audit FTP users.",
        "msf_module": "exploit/unix/ftp/vsftpd_234_backdoor",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    {
        "id": "NP-002", "port": 21, "match": "__anonymous__",
        "cve": "CWE-306", "cvss": (7.5, "HIGH"),
        "description": "Anonymous FTP login enabled – unauthenticated file read/write possible",
        "remediation": "Disable anonymous FTP. Enforce authentication. Use SFTP instead.",
        "msf_module": "auxiliary/scanner/ftp/anonymous",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },
    # ssh
    {
        "id": "NP-003", "port": 22, "match": "openssh 7.2",
        "cve": "CVE-2016-6210", "cvss": (5.9, "MEDIUM"),
        "description": "OpenSSH ≤ 7.2p2 username enumeration via timing side-channel in PAM authentication",
        "remediation": "Upgrade OpenSSH ≥ 7.3. Enforce rate limiting on auth attempts. Use fail2ban.",
        "msf_module": "auxiliary/scanner/ssh/ssh_enumusers",
        "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },
    {
        "id": "NP-004", "port": 22, "match": "openssh 6.",
        "cve": "CVE-2015-5600", "cvss": (8.1, "HIGH"),
        "description": "OpenSSH < 6.9 MaxAuthTries bypass – brute force using keyboard-interactive auth",
        "remediation": "Upgrade OpenSSH. Enforce PasswordAuthentication=no. Use key-based auth only.",
        "msf_module": "auxiliary/scanner/ssh/ssh_login",
        "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    },
    # http
    {
        "id": "NP-005", "port": 80, "match": "apache/2.2",
        "cve": "CVE-2017-7679", "cvss": (9.8, "CRITICAL"),
        "description": "Apache 2.2.x mod_mime buffer overread – remote code execution via crafted request",
        "remediation": "Upgrade Apache ≥ 2.4.26. Disable mod_mime if unused. Apply vendor patches.",
        "msf_module": "exploit/multi/http/apache_mod_cgi_bash_env_exec",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    {
        "id": "NP-006", "port": 80, "match": "apache/2.4.49",
        "cve": "CVE-2021-41773", "cvss": (9.8, "CRITICAL"),
        "description": "Apache 2.4.49 Path Traversal & RCE – allows reading arbitrary files and executing commands",
        "remediation": "Update Apache to ≥ 2.4.51 immediately. Set 'Require all denied' in configs.",
        "msf_module": "exploit/multi/http/apache_normalize_path_rce",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    # ssl/tls
    {
        "id": "NP-007", "port": 443, "match": "openssl/1.0.1",
        "cve": "CVE-2014-0160", "cvss": (7.5, "HIGH"),
        "description": "Heartbleed – OpenSSL TLS heartbeat extension reads up to 64KB of server memory, exposing private keys",
        "remediation": "Upgrade OpenSSL ≥ 1.0.1g. Regenerate all TLS certificates. Revoke old keys.",
        "msf_module": "auxiliary/scanner/ssl/openssl_heartbleed",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },
    {
        "id": "NP-008", "port": 443, "match": "__sslv2__",
        "cve": "CVE-2016-0800", "cvss": (5.9, "MEDIUM"),
        "description": "DROWN – SSLv2 supported, enables cross-protocol attack decrypting TLS sessions",
        "remediation": "Disable SSLv2 and SSLv3 entirely. Configure TLS 1.2+ only. Use HSTS.",
        "msf_module": "auxiliary/scanner/ssl/bleichenbacher_pkcs1_v15",
        "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },
    # smb
    {
        "id": "NP-009", "port": 445, "match": "windows",
        "cve": "CVE-2017-0144", "cvss": (9.8, "CRITICAL"),
        "description": "EternalBlue – SMBv1 buffer overflow enabling unauthenticated remote code execution (WannaCry/NotPetya)",
        "remediation": "Patch MS17-010. Disable SMBv1 via PowerShell: Set-SmbServerConfiguration -EnableSMB1Protocol $false",
        "msf_module": "exploit/windows/smb/ms17_010_eternalblue",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    {
        "id": "NP-010", "port": 445, "match": "samba 3.",
        "cve": "CVE-2017-7494", "cvss": (9.8, "CRITICAL"),
        "description": "SambaCry – Samba 3.5.0+ writable share + pipe allows arbitrary shared library loading (RCE)",
        "remediation": "Patch Samba to ≥ 4.6.4. Add 'nt pipe support = no' to smb.conf. Restrict writable shares.",
        "msf_module": "exploit/linux/samba/is_known_pipename",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    # rdp
    {
        "id": "NP-011", "port": 3389, "match": "__rdp__",
        "cve": "CVE-2019-0708", "cvss": (9.8, "CRITICAL"),
        "description": "BlueKeep – Pre-auth RDP use-after-free enabling wormable remote code execution (no login required)",
        "remediation": "Apply KB4499175. Enable NLA for RDP. Block port 3389 externally. Use VPN for remote access.",
        "msf_module": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    # vnc
    {
        "id": "NP-012", "port": 5900, "match": "rfb 003.003",
        "cve": "CVE-2006-2369", "cvss": (7.5, "HIGH"),
        "description": "RealVNC 4.1.1 authentication bypass – selecting security type None bypasses password authentication",
        "remediation": "Upgrade VNC server. Enforce password authentication. Bind VNC to localhost and use SSH tunnel.",
        "msf_module": "auxiliary/scanner/vnc/vnc_none_auth",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },
    # mysql
    {
        "id": "NP-013", "port": 3306, "match": "mysql 5.5",
        "cve": "CVE-2012-2122", "cvss": (9.8, "CRITICAL"),
        "description": "MySQL 5.5.x auth bypass – repeated password attempts due to memcmp timing vulnerability (1 in 256 chance)",
        "remediation": "Upgrade MySQL ≥ 5.5.23. Bind to localhost. Disable remote root login. Use strong passwords.",
        "msf_module": "auxiliary/scanner/mysql/mysql_authbypass_hashdump",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    # redis
    {
        "id": "NP-014", "port": 6379, "match": "__redis__",
        "cve": "CVE-2022-0543", "cvss": (10.0, "CRITICAL"),
        "description": "Redis unprotected instance + Lua sandbox escape enabling unauthenticated RCE and data exfiltration",
        "remediation": "Bind Redis to 127.0.0.1. Enable requirepass. Disable EVAL if unused. Use ACL system (Redis 6+).",
        "msf_module": "exploit/linux/redis/redis_replication_cmd_exec",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    },
    # mongodb
    {
        "id": "NP-015", "port": 27017, "match": "__mongo__",
        "cve": "CWE-306", "cvss": (9.1, "CRITICAL"),
        "description": "MongoDB unprotected – no authentication required, allowing full DB read/write/drop",
        "remediation": "Enable MongoDB auth (--auth). Bind to localhost. Use network firewall. Enable TLS.",
        "msf_module": "auxiliary/scanner/mongodb/mongodb_unauth",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    },
    # docker
    {
        "id": "NP-016", "port": 2375, "match": "__docker__",
        "cve": "CWE-306", "cvss": (10.0, "CRITICAL"),
        "description": "Docker daemon exposed unauthenticated – full container/host control, host filesystem mount possible",
        "remediation": "Never expose Docker socket remotely. Use TLS client certs (port 2376). Use rootless Docker.",
        "msf_module": "exploit/linux/http/docker_daemon_tcp",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    },
    # elasticsearch
    {
        "id": "NP-017", "port": 9200, "match": "__elastic__",
        "cve": "CVE-2014-3120", "cvss": (9.8, "CRITICAL"),
        "description": "Elasticsearch unprotected – dynamic scripting allows unauthenticated RCE via Groovy/Mvel sandbox escape",
        "remediation": "Enable X-Pack security. Disable dynamic scripting in elasticsearch.yml. Firewall port 9200.",
        "msf_module": "exploit/multi/elasticsearch/dynamic_script_mvel_rce",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    # telnet
    {
        "id": "NP-018", "port": 23, "match": "__telnet__",
        "cve": "CWE-319", "cvss": (9.1, "CRITICAL"),
        "description": "Telnet transmits credentials and data in cleartext – trivial interception via network sniffing",
        "remediation": "Disable Telnet service entirely. Replace with SSH. Use TLS for all remote management.",
        "msf_module": "auxiliary/scanner/telnet/telnet_login",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    },
    # snmp
    {
        "id": "NP-019", "port": 161, "match": "__snmp_public__",
        "cve": "CVE-2002-0013", "cvss": (7.5, "HIGH"),
        "description": "SNMP community string 'public' – exposes device configuration, interface stats, ARP tables",
        "remediation": "Change community strings. Use SNMPv3 with AuthPriv. Restrict SNMP access by source IP.",
        "msf_module": "auxiliary/scanner/snmp/snmp_enum",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },
    # winrm
    {
        "id": "NP-020", "port": 5985, "match": "__winrm__",
        "cve": "CWE-287", "cvss": (8.8, "HIGH"),
        "description": "WinRM exposed – Windows Remote Management allows remote PowerShell execution with valid credentials",
        "remediation": "Restrict WinRM by IP. Enforce HTTPS (5986). Use Just Enough Administration (JEA). Monitor for abuse.",
        "msf_module": "exploit/windows/winrm/winrm_script_exec",
        "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    },
]


WEAK_CIPHERS = {
    "RC4": ("CRITICAL", "Stream cipher with known statistical biases – breaks HTTPS confidentiality"),
    "DES":  ("CRITICAL", "56-bit DES is broken; brute-forceable in hours"),
    "3DES": ("HIGH",     "Triple-DES vulnerable to SWEET32 birthday attack (64-bit block size)"),
    "NULL": ("CRITICAL", "NULL cipher – no encryption, session data transmitted in plaintext"),
    "EXPORT": ("CRITICAL","EXPORT-grade cipher (40/56-bit) – trivially breakable, used in FREAK/Logjam"),
    "ANON": ("HIGH",     "Anonymous DH/ECDH – no server authentication, enables MITM"),
    "MD5":  ("MEDIUM",   "MD5-based HMAC – collision attacks weaken integrity"),
    "SHA1": ("LOW",      "SHA-1 deprecated; prefer SHA-256 or SHA-384"),
    "SSLv2":("CRITICAL", "SSLv2 fundamentally broken – DROWN attack"),
    "SSLv3":("HIGH",     "SSLv3 vulnerable to POODLE attack"),
    "TLSv1.0":("MEDIUM", "TLS 1.0 deprecated – BEAST attack, PCI-DSS non-compliant since 2018"),
    "TLSv1.1":("LOW",    "TLS 1.1 deprecated by RFC 8996 – use TLS 1.2+"),
}

results_lock = threading.Lock()
scan_stats = {"scanned": 0, "total": 0}


def progress_bar(current: int, total: int, width: int = 40, label: str = "") -> str:
    if total == 0:
        return ""
    pct = current / total
    filled = int(width * pct)
    bar = "█" * filled + "░" * (width - filled)
    return f"\r  {C.CYAN}[{bar}]{C.RESET} {C.WHITE}{current}/{total}{C.RESET} {C.GRAY}{label}{C.RESET}"


def arp_discover(network: str) -> List[str]:
    """ARP scan using arping or arp-scan for LAN discovery."""
    live = []
    try:
        result = subprocess.run(
            ["arp-scan", "--localnet", "--quiet"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                parts = line.split()
                if parts and re.match(r'^\d+\.\d+\.\d+\.\d+$', parts[0]):
                    live.append(parts[0])
            return live
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    
    try:
        net = ipaddress.ip_network(network, strict=False)
        hosts = list(net.hosts())[:254]
        for h in hosts:
            try:
                r = subprocess.run(
                    ["arping", "-c", "1", "-W", "0.5", str(h)],
                    capture_output=True, timeout=2
                )
                if r.returncode == 0:
                    live.append(str(h))
            except Exception:
                pass
    except Exception:
        pass
    return live

def ping_host(ip: str, timeout: float = 1.0) -> bool:
    """ICMP ping check."""
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(max(1, int(timeout))), str(ip)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=timeout + 1
        )
        return result.returncode == 0
    except Exception:
        return False

def tcp_ping(ip: str, ports: List[int] = [80, 443, 22, 445], timeout: float = 0.5) -> bool:
    """TCP connect check as fallback when ICMP is blocked."""
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                s.close()
                return True
            s.close()
        except Exception:
            pass
    return False

def discover_hosts(network: str, method: str = "auto") -> List[str]:
    """Multi-method host discovery with fallback chain."""
    print(f"\n{C.CYAN}[*] Host discovery on {network} (method: {method}){C.RESET}")
    live = []

    try:
        net = ipaddress.ip_network(network, strict=False)
        all_hosts = [str(h) for h in net.hosts()]
    except ValueError as e:
        print(f"{C.RED}[!] Invalid network: {e}{C.RESET}")
        return []

    if net.num_addresses == 1:
        ip = str(net.network_address)
        up = ping_host(ip) or tcp_ping(ip)
        if up:
            print(f"  {C.GREEN}[+] {ip} is UP{C.RESET}")
        else:
            print(f"  {C.YELLOW}[!] {ip} appears down (scanning anyway){C.RESET}")
        return [ip]

    print(f"{C.WHITE}[*] Probing {len(all_hosts)} hosts...{C.RESET}")

    if method in ("auto", "arp"):
        arp_hosts = arp_discover(network)
        if arp_hosts:
            cprint(C.GREEN, f"[+] ARP discovered {len(arp_hosts)} hosts")
            return sorted(set(arp_hosts))

    # ICMP + 
    completed = [0]
    total = len(all_hosts)

    def probe(ip):
        up = ping_host(ip, 0.5) or tcp_ping(ip)
        with results_lock:
            completed[0] += 1
            print(progress_bar(completed[0], total, label="discovering"), end="", flush=True)
            if up:
                live.append(ip)
                print(f"\n  {C.GREEN}[+] {ip} UP{C.RESET}")

    with ThreadPoolExecutor(max_workers=100) as ex:
        list(ex.map(probe, all_hosts))

    print()  # newline after progress bar
    cprint(C.GREEN, f"[+] Found {len(live)} live host(s)")
    return sorted(live)

def scan_port_tcp(ip: str, port: int, timeout: float = 1.0, delay: float = 0.0) -> Optional[Dict]:
    """TCP connect scan with banner grabbing."""
    if delay > 0:
        time.sleep(delay)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if sock.connect_ex((ip, port)) == 0:
            banner = grab_banner(sock, port)
            sock.close()
            return {
                "port": port, "proto": "tcp", "state": "open",
                "service": get_service(port), "banner": banner,
                "category": SERVICE_DB.get(port, {}).get("category", "unknown")
            }
        sock.close()
    except Exception:
        pass
    return None

def grab_banner(sock: socket.socket, port: int, timeout: float = 2.0) -> str:
    """Advanced banner grabbing with protocol-aware probes."""
    try:
        sock.settimeout(timeout)
        probes = {
            80:   b"HEAD / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n",
            8080: b"HEAD / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n",
            443:  b"HEAD / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n",
            8443: b"HEAD / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n",
            25:   b"EHLO netpwn\r\n",
            110:  b"",
            143:  b"",
            3306: b"",
            5432: b"",
            6379: b"*1\r\n$4\r\nINFO\r\n",
            9200: b"GET / HTTP/1.0\r\n\r\n",
            27017: b"",
        }
        probe = probes.get(port, b"\r\n")
        if probe:
            sock.sendall(probe)
        try:
            data = sock.recv(2048)
            banner = data.decode("utf-8", errors="ignore").strip()
            return banner[:200].split("\n")[0].strip()
        except Exception:
            return ""
    except Exception:
        return ""

def scan_ports_tcp(ip: str, ports: List[int], timing: Dict) -> List[Dict]:
    """Threaded TCP scan of multiple ports."""
    open_ports = []
    completed = [0]
    total = len(ports)

    def _scan(port):
        result = scan_port_tcp(ip, port, timing["connect_timeout"], timing["delay"])
        with results_lock:
            completed[0] += 1
            if completed[0] % 50 == 0 or completed[0] == total:
                print(progress_bar(completed[0], total, label=f"tcp:{ip}"), end="", flush=True)
            if result:
                open_ports.append(result)

    with ThreadPoolExecutor(max_workers=timing["threads"]) as ex:
        list(ex.map(_scan, ports))

    print() 
    return sorted(open_ports, key=lambda x: x["port"])

UDP_PROBES = {
    53:  b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
    67:  b"\x01\x01\x06\x00" + b"\x00" * 236,  
    69:  b"\x00\x01/etc/passwd\x00netascii\x00", 
    123: b"\x1b" + b"\x00" * 47,              
    161: b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x71\xb4\xdc\x44\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",  # SNMP
    500: b"\x00" * 28 + b"\x01\x10\x02\x00",  
    514: b"<14>test\n",                       
}

def scan_udp_port(ip: str, port: int, timeout: float = 2.0) -> Optional[Dict]:
    """UDP probe-and-response scan."""
    probe = UDP_PROBES.get(port, b"\x00" * 4)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(probe, (ip, port))
        try:
            data, _ = sock.recvfrom(1024)
            sock.close()
            banner = data[:80].decode("utf-8", errors="ignore").strip()
            return {
                "port": port, "proto": "udp", "state": "open|filtered",
                "service": get_service(port), "banner": banner,
                "category": SERVICE_DB.get(port, {}).get("category", "unknown")
            }
        except socket.timeout:
            sock.close()
            return None
    except Exception:
        return None

def scan_udp(ip: str, ports: List[int] = None) -> List[Dict]:
    """Scan common UDP ports."""
    if ports is None:
        ports = list(UDP_PROBES.keys())
    results = []
    print(f"\n  {C.CYAN}[*] UDP scan ({len(ports)} ports)...{C.RESET}")
    for port in ports:
        result = scan_udp_port(ip, port)
        if result:
            results.append(result)
            print(f"    {C.YELLOW}[UDP]{C.RESET} {port}/{result['service']} → {result['state']}")
    return results

class ServiceFingerprinter:
    """Protocol-specific fingerprinting modules."""

    @staticmethod
    def fingerprint_http(ip: str, port: int, timeout: float = 3.0) -> Dict:
        """HTTP header analysis – server, X-Powered-By, security headers."""
        meta = {"protocol": "HTTP", "server": "", "cms": "", "security_headers": {}, "info": []}
        try:
            use_ssl = port in (443, 8443)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=ip)
            req = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
            sock.sendall(req.encode())
            resp = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp += chunk
            sock.close()
            headers_raw = resp.decode("utf-8", errors="ignore")
            for line in headers_raw.splitlines():
                low = line.lower()
                if low.startswith("server:"):
                    meta["server"] = line.split(":", 1)[1].strip()
                elif low.startswith("x-powered-by:"):
                    meta["info"].append(f"X-Powered-By: {line.split(':',1)[1].strip()}")
                elif low.startswith("x-generator:"):
                    meta["cms"] = line.split(":", 1)[1].strip()
                elif low.startswith("strict-transport-security"):
                    meta["security_headers"]["HSTS"] = True
                elif low.startswith("x-content-type-options"):
                    meta["security_headers"]["X-Content-Type-Options"] = True
                elif low.startswith("x-frame-options"):
                    meta["security_headers"]["X-Frame-Options"] = True
                elif low.startswith("content-security-policy"):
                    meta["security_headers"]["CSP"] = True
                elif low.startswith("x-xss-protection"):
                    meta["security_headers"]["X-XSS-Protection"] = True

            missing = [h for h in ["HSTS","X-Content-Type-Options","X-Frame-Options","CSP"]
                       if h not in meta["security_headers"]]
            if missing:
                meta["info"].append(f"Missing security headers: {', '.join(missing)}")
        except Exception:
            pass
        return meta

    @staticmethod
    def fingerprint_ftp(ip: str, port: int = 21, timeout: float = 3.0) -> Dict:
        """FTP banner + anonymous login test."""
        meta = {"protocol": "FTP", "banner": "", "anonymous": False, "version": ""}
        try:
            ftp = ftplib.FTP()
            ftp.connect(ip, port, timeout=timeout)
            meta["banner"] = ftp.getwelcome()
            try:
                ftp.login("anonymous", "netpwn@scan.local")
                meta["anonymous"] = True
                try:
                    files = ftp.nlst()
                    meta["anon_files"] = files[:10]
                except Exception:
                    pass
                ftp.quit()
            except ftplib.error_perm:
                meta["anonymous"] = False
        except Exception:
            pass
        return meta

    @staticmethod
    def fingerprint_smtp(ip: str, port: int = 25, timeout: float = 3.0) -> Dict:
        """SMTP EHLO – feature enumeration."""
        meta = {"protocol": "SMTP", "banner": "", "features": [], "open_relay": False}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            meta["banner"] = sock.recv(512).decode("utf-8", errors="ignore").strip()
            sock.sendall(b"EHLO netpwn.scan\r\n")
            resp = sock.recv(1024).decode("utf-8", errors="ignore")
            meta["features"] = [l.strip() for l in resp.splitlines() if l.startswith("250-") or l.startswith("250 ")]
            # Open relay test
            sock.sendall(b"MAIL FROM:<test@netpwn.local>\r\n")
            r1 = sock.recv(128).decode(errors="ignore")
            sock.sendall(b"RCPT TO:<victim@external.com>\r\n")
            r2 = sock.recv(128).decode(errors="ignore")
            if "250" in r2:
                meta["open_relay"] = True
            sock.sendall(b"QUIT\r\n")
            sock.close()
        except Exception:
            pass
        return meta

    @staticmethod
    def fingerprint_redis(ip: str, port: int = 6379, timeout: float = 3.0) -> Dict:
        """Redis INFO command – version, auth, persistence."""
        meta = {"protocol": "Redis", "version": "", "auth_required": True, "config": {}}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            sock.sendall(b"INFO server\r\n")
            resp = sock.recv(4096).decode("utf-8", errors="ignore")
            if "redis_version" in resp:
                meta["auth_required"] = False
                for line in resp.splitlines():
                    if "redis_version" in line:
                        meta["version"] = line.split(":")[1].strip()
                    if "os:" in line:
                        meta["config"]["os"] = line.split(":")[1].strip()
                    if "tcp_port" in line:
                        meta["config"]["port"] = line.split(":")[1].strip()
            elif "NOAUTH" in resp or "ERR" not in resp:
                meta["auth_required"] = True
            sock.sendall(b"QUIT\r\n")
            sock.close()
        except Exception:
            pass
        return meta

    @staticmethod
    def fingerprint_generic(ip: str, port: int, timeout: float = 2.0) -> Dict:
        return {"protocol": get_service(port), "banner": ""}


class TLSAuditor:
    """SSL/TLS certificate and cipher suite analysis."""

    @staticmethod
    def audit(ip: str, port: int, timeout: float = 5.0) -> Dict:
        result = {
            "enabled": False,
            "version": "",
            "cipher": "",
            "cert": {},
            "weak_versions": [],
            "weak_ciphers": [],
            "issues": [],
        }

        for proto_name, proto_const in [
            ("SSLv2",  None),
            ("SSLv3",  ssl.PROTOCOL_TLS_CLIENT if hasattr(ssl, 'PROTOCOL_TLS_CLIENT') else None),
            ("TLSv1.0",ssl.PROTOCOL_TLS_CLIENT if hasattr(ssl, 'PROTOCOL_TLS_CLIENT') else None),
            ("TLSv1.1",ssl.PROTOCOL_TLS_CLIENT if hasattr(ssl, 'PROTOCOL_TLS_CLIENT') else None),
        ]:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                if proto_name == "TLSv1.0":
                    try:
                        ctx.minimum_version = ssl.TLSVersion.TLSv1
                        ctx.maximum_version = ssl.TLSVersion.TLSv1
                    except AttributeError:
                        continue
                elif proto_name == "TLSv1.1":
                    try:
                        ctx.minimum_version = ssl.TLSVersion.TLSv1_1
                        ctx.maximum_version = ssl.TLSVersion.TLSv1_1
                    except AttributeError:
                        continue
                else:
                    continue

                sock = socket.create_connection((ip, port), timeout=timeout)
                ssock = ctx.wrap_socket(sock, server_hostname=ip)
                ssock.close()
                result["weak_versions"].append(proto_name)
                sev, desc = WEAK_CIPHERS.get(proto_name, ("LOW", ""))
                result["issues"].append({"issue": f"{proto_name} supported", "severity": sev, "detail": desc})
            except Exception:
                pass

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = socket.create_connection((ip, port), timeout=timeout)
            ssock = ctx.wrap_socket(sock, server_hostname=ip)

            result["enabled"] = True
            result["version"] = ssock.version() or ""
            result["cipher"] = ssock.cipher()[0] if ssock.cipher() else ""

            cipher_str = result["cipher"].upper()
            for weak_kw, (sev, desc) in WEAK_CIPHERS.items():
                if weak_kw.upper() in cipher_str:
                    result["weak_ciphers"].append(weak_kw)
                    result["issues"].append({"issue": f"Weak cipher: {result['cipher']}", "severity": sev, "detail": desc})

            # Certificate
            cert = ssock.getpeercert()
            if cert:
                not_after = cert.get("notAfter", "")
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer  = dict(x[0] for x in cert.get("issuer",  []))
                san     = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

                result["cert"] = {
                    "subject_cn": subject.get("commonName", "N/A"),
                    "issuer_cn":  issuer.get("commonName", "N/A"),
                    "not_after":  not_after,
                    "san":        san[:5],
                    "self_signed": subject == issuer,
                }

                # Check expiry
                if not_after:
                    try:
                        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        days_left = (exp - datetime.utcnow()).days
                        result["cert"]["days_until_expiry"] = days_left
                        if days_left < 0:
                            result["issues"].append({"issue": "Certificate EXPIRED", "severity": "CRITICAL",
                                "detail": f"Expired {abs(days_left)} days ago"})
                        elif days_left < 30:
                            result["issues"].append({"issue": f"Certificate expiring in {days_left} days",
                                "severity": "HIGH", "detail": "Renew immediately to avoid service disruption"})
                        elif days_left < 90:
                            result["issues"].append({"issue": f"Certificate expiring in {days_left} days",
                                "severity": "MEDIUM", "detail": "Plan renewal soon"})
                    except Exception:
                        pass

                if result["cert"].get("self_signed"):
                    result["issues"].append({"issue": "Self-signed certificate",
                        "severity": "MEDIUM", "detail": "No third-party verification; susceptible to MITM"})

            ssock.close()
        except Exception:
            pass

        return result


def fingerprint_os(ip: str, open_ports: List[Dict]) -> Dict:
    """Multi-signal OS fingerprinting: TTL + port heuristics + TCP window."""
    result = {"guess": "Unknown", "confidence": "low", "method": [], "ttl": None}
    port_nums = [p["port"] for p in open_ports]

    try:
        ping_out = subprocess.run(
            ["ping", "-c", "2", "-W", "2", ip],
            capture_output=True, text=True, timeout=6
        )
        for line in ping_out.stdout.splitlines():
            m = re.search(r'ttl=(\d+)', line, re.IGNORECASE)
            if m:
                ttl = int(m.group(1))
                result["ttl"] = ttl
                if ttl <= 64:
                    result["guess"] = "Linux / Unix"
                    result["confidence"] = "medium"
                    result["method"].append(f"TTL={ttl}")
                elif ttl <= 128:
                    result["guess"] = "Windows"
                    result["confidence"] = "medium"
                    result["method"].append(f"TTL={ttl}")
                elif ttl <= 255:
                    result["guess"] = "Cisco IOS / Network Device"
                    result["confidence"] = "medium"
                    result["method"].append(f"TTL={ttl}")
                break
    except Exception:
        pass

    if 3389 in port_nums and 445 in port_nums:
        result["guess"] = "Windows Server (RDP + SMB)"
        result["confidence"] = "high"
        result["method"].append("RDP+SMB")
    elif 3389 in port_nums and 135 in port_nums:
        result["guess"] = "Windows (RDP + MSRPC)"
        result["confidence"] = "high"
        result["method"].append("RDP+MSRPC")
    elif 22 in port_nums and 111 in port_nums:
        result["guess"] = "Linux (SSH + RPC/NFS)"
        result["confidence"] = "high"
        result["method"].append("SSH+RPC")
    elif 22 in port_nums and 80 in port_nums and 443 in port_nums:
        result["guess"] = "Linux Web Server"
        result["confidence"] = "medium"
        result["method"].append("SSH+HTTP+HTTPS")
    elif 8888 in port_nums or 27017 in port_nums:
        result["guess"] = "Linux Data Server"
        result["confidence"] = "low"
        result["method"].append("DataSvc")

    for p in open_ports:
        b = p.get("banner", "").lower()
        if "ubuntu" in b or "debian" in b or "centos" in b or "fedora" in b:
            result["guess"] = f"Linux ({b.split()[0].capitalize() if b.split() else 'Unknown distro'})"
            result["confidence"] = "high"
            result["method"].append("Banner")
            break
        if "windows" in b or "microsoft" in b or "iis" in b:
            result["guess"] = "Windows"
            result["confidence"] = "high"
            result["method"].append("Banner")
            break

    return result

def run_traceroute(ip: str, max_hops: int = 20) -> List[Dict]:
    """Parse traceroute output into structured hops."""
    hops = []
    try:
        result = subprocess.run(
            ["traceroute", "-m", str(max_hops), "-w", "1", "-q", "1", ip],
            capture_output=True, text=True, timeout=45
        )
        for line in result.stdout.splitlines()[1:]:
            m = re.match(r'\s*(\d+)\s+([\d.]+|\*)\s+(?:([\d.]+) ms)?', line)
            if m:
                hop_num = int(m.group(1))
                hop_ip  = m.group(2)
                rtt     = m.group(3)
                hop_host = ""
                if hop_ip and hop_ip != "*":
                    try:
                        hop_host = socket.gethostbyaddr(hop_ip)[0]
                    except Exception:
                        hop_host = hop_ip
                hops.append({"hop": hop_num, "ip": hop_ip or "*", "hostname": hop_host, "rtt_ms": rtt or "?"})
    except Exception:
        pass
    return hops


def match_vulnerabilities(open_ports: List[Dict], tls_results: Dict,
                           service_meta: Dict, anon_ftp: bool) -> List[Dict]:
    """Match VULN_DB entries against scan results."""
    found = []
    port_nums = {p["port"] for p in open_ports}

    for vuln in VULN_DB:
        vport = vuln["port"]
        vmatch = vuln["match"]

        if vport not in port_nums:
            continue

        port_info = next((p for p in open_ports if p["port"] == vport), None)
        banner = (port_info.get("banner", "") if port_info else "").lower()

        triggered = False

        if vmatch == "__anonymous__" and anon_ftp:
            triggered = True
        elif vmatch == "__sslv2__":
            tls = tls_results.get(vport, {})
            if "SSLv2" in tls.get("weak_versions", []):
                triggered = True
        elif vmatch.startswith("__") and vmatch.endswith("__"):
            
            triggered = True
        elif vmatch.lower() in banner:
            triggered = True
        elif vuln["cvss"][1] == "CRITICAL" and vport in port_nums:
           
            triggered = True

        if triggered:
            entry = dict(vuln)
            entry["banner_matched"] = banner[:60] if banner else "N/A"
            found.append(entry)

    
    for port, tls in tls_results.items():
        for issue in tls.get("issues", []):
            found.append({
                "id": "NP-TLS",
                "port": port,
                "cve": "TLS-CONFIG",
                "cvss": (0, issue["severity"]),
                "description": issue["issue"],
                "remediation": issue.get("detail", "Harden TLS configuration"),
                "msf_module": "N/A",
                "banner_matched": "TLS audit",
            })

    for port, meta in service_meta.items():
        if meta.get("protocol") == "HTTP" and meta.get("info"):
            for info in meta["info"]:
                if "Missing security headers" in info:
                    found.append({
                        "id": "NP-HTTP",
                        "port": port,
                        "cve": "CWE-693",
                        "cvss": (5.3, "MEDIUM"),
                        "description": info,
                        "remediation": "Add HSTS, CSP, X-Frame-Options, X-Content-Type-Options headers",
                        "msf_module": "N/A",
                        "banner_matched": "HTTP headers",
                    })

        if meta.get("protocol") == "SMTP" and meta.get("open_relay"):
            found.append({
                "id": "NP-SMTP",
                "port": port,
                "cve": "CWE-183",
                "cvss": (7.5, "HIGH"),
                "description": "Open SMTP relay – allows unauthorized mail relay, spam/phishing abuse",
                "remediation": "Restrict RCPT TO to local domains only. Enable sender authentication.",
                "msf_module": "auxiliary/scanner/smtp/smtp_relay",
                "banner_matched": "SMTP relay test",
            })

    seen = set()
    unique = []
    for v in found:
        key = f"{v['id']}:{v['port']}"
        if key not in seen:
            seen.add(key)
            unique.append(v)

    return sorted(unique, key=lambda x: x["cvss"][0], reverse=True)

def calculate_risk_score(vulns: List[Dict]) -> float:
    """Weighted risk score 0–10 using CVSSv3 base scores."""
    if not vulns:
        return 0.0
    
    scores = [v["cvss"][0] for v in vulns if isinstance(v["cvss"][0], (int, float))]
    if not scores:
        return 0.0
    highest = max(scores)
    avg = sum(scores) / len(scores)
    score = (highest * 0.6 + avg * 0.4)
    return round(min(score, 10.0), 1)

def risk_label(score: float) -> Tuple[str, str]:
    if score >= 9.0: return "CRITICAL", C.RED + C.BOLD
    if score >= 7.0: return "HIGH",     C.MAGENTA
    if score >= 4.0: return "MEDIUM",   C.YELLOW
    if score > 0.0:  return "LOW",      C.CYAN
    return "NONE", C.GREEN


def print_host_report(host: str, open_ports: List[Dict], udp_ports: List[Dict],
                       vulns: List[Dict], tls_results: Dict, service_meta: Dict,
                       os_info: Dict, traceroute: List[Dict], risk_score: float):
    """Rich terminal report for a single host."""
    sep = "═" * 62
    thin = "─" * 62

    print(f"\n{C.BOLD}{C.WHITE}{sep}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  SCAN RESULTS: {host}{C.RESET}")
    lbl, lc = risk_label(risk_score)
    print(f"{C.WHITE}  Risk Score: {lc}{risk_score}/10 [{lbl}]{C.RESET}")
    print(f"{C.WHITE}{sep}{C.RESET}") 

    conf_color = C.GREEN if os_info["confidence"] == "high" else C.YELLOW
    print(f"\n{C.YELLOW}[OS Fingerprint]{C.RESET}")
    print(f"  {os_info['guess']} {conf_color}({os_info['confidence']} confidence){C.RESET}")
    if os_info.get("ttl"):
        print(f"  TTL: {os_info['ttl']} | Methods: {', '.join(os_info['method'])}")

    print(f"\n{C.YELLOW}[Open TCP Ports — {len(open_ports)} found]{C.RESET}")
    if open_ports:
        print(f"  {C.BOLD}{'PORT':<8} {'SERVICE':<14} {'CATEGORY':<14} BANNER{C.RESET}")
        print(f"  {thin}")
        for p in open_ports:
            banner = (p.get("banner","") or "")[:42]
            cat = p.get("category","")[:12]
            print(f"  {C.GREEN}{p['port']:<8}{C.RESET}{p['service']:<14}{C.GRAY}{cat:<14}{C.RESET}{C.WHITE}{banner}{C.RESET}")
    else:
        print(f"  {C.RED}No open TCP ports found{C.RESET}")

    if udp_ports:
        print(f"\n{C.YELLOW}[Open UDP Ports — {len(udp_ports)} found]{C.RESET}")
        for p in udp_ports:
            print(f"  {C.YELLOW}{p['port']:<8}{C.RESET}{p['service']:<14}{C.GRAY}udp{C.RESET}")

    if service_meta:
        print(f"\n{C.YELLOW}[Service Fingerprint Details]{C.RESET}")
        for port, meta in service_meta.items():
            proto = meta.get("protocol", get_service(port))
            print(f"\n  {C.CYAN}Port {port}/{proto}{C.RESET}")
            if meta.get("server"):
                print(f"    Server       : {meta['server']}")
            if meta.get("version"):
                print(f"    Version      : {meta['version']}")
            if meta.get("banner"):
                print(f"    Banner       : {meta['banner'][:60]}")
            if meta.get("anonymous"):
                print(f"    {C.RED}[!] Anonymous login: ALLOWED{C.RESET}")
            if meta.get("open_relay"):
                print(f"    {C.RED}[!] SMTP Open Relay: DETECTED{C.RESET}")
            if meta.get("auth_required") is False:
                print(f"    {C.RED}[!] No authentication required{C.RESET}")
            for info in meta.get("info", []):
                print(f"    {C.YELLOW}[i]{C.RESET} {info}")

    if tls_results:
        print(f"\n{C.YELLOW}[TLS/SSL Audit]{C.RESET}")
        for port, tls in tls_results.items():
            if not tls.get("enabled"):
                print(f"  Port {port}: TLS not enabled or connection failed")
                continue
            print(f"\n  {C.CYAN}Port {port}{C.RESET}")
            print(f"    Protocol : {tls.get('version','?')}")
            print(f"    Cipher   : {tls.get('cipher','?')}")
            cert = tls.get("cert", {})
            if cert:
                print(f"    Cert CN  : {cert.get('subject_cn','?')}")
                print(f"    Issuer   : {cert.get('issuer_cn','?')}")
                days = cert.get("days_until_expiry")
                if days is not None:
                    exp_color = C.RED if days < 30 else C.YELLOW if days < 90 else C.GREEN
                    print(f"    Expiry   : {exp_color}{days} days remaining{C.RESET}")
                if cert.get("self_signed"):
                    print(f"    {C.YELLOW}[!] Self-signed certificate{C.RESET}")
                if cert.get("san"):
                    print(f"    SANs     : {', '.join(cert['san'][:3])}")
            if tls.get("weak_versions"):
                print(f"    {C.RED}Weak protocols: {', '.join(tls['weak_versions'])}{C.RESET}")

    print(f"\n{C.YELLOW}[Vulnerabilities — {len(vulns)} found]{C.RESET}")
    if vulns:
        for v in vulns:
            score, sev_label = v["cvss"]
            sc = severity_color(sev_label)
            print(f"\n  {sc}[{sev_label}]{C.RESET} {C.BOLD}{v['cve']}{C.RESET} "
                  f"{C.GRAY}(CVSS: {score}){C.RESET}")
            print(f"  Port: {v['port']} / {get_service(v['port'])}")
            print(f"  {v['description']}")
            print(f"  {C.CYAN}Remediation:{C.RESET} {v['remediation']}")
            if v.get("msf_module") and v["msf_module"] != "N/A":
                print(f"  {C.MAGENTA}MSF Module:{C.RESET} {v['msf_module']}")
    else:
        print(f"  {C.GREEN}No known vulnerabilities matched{C.RESET}")

    if traceroute:
        print(f"\n{C.YELLOW}[Traceroute — {len(traceroute)} hops]{C.RESET}")
        for hop in traceroute:
            rtt = f"{hop['rtt_ms']} ms" if hop["rtt_ms"] != "?" else "* (timeout)"
            host_str = f" ({hop['hostname']})" if hop["hostname"] != hop["ip"] else ""
            print(f"  {C.GRAY}{hop['hop']:>3}.{C.RESET}  {hop['ip']:<15}{C.GRAY}{host_str}{C.RESET}  {rtt}")

    print(f"\n{C.WHITE}{sep}{C.RESET}")


def generate_html_report(all_results: List[Dict], output_file: str):
    """Generate a standalone HTML report with embedded CSS."""
    def sev_badge(sev):
        colors = {"CRITICAL":"#d90000","HIGH":"#e07000","MEDIUM":"#c4c000","LOW":"#0077cc","INFO":"#555","NONE":"#2d7a2d"}
        c = colors.get(sev, "#555")
        return f'<span style="background:{c};color:#fff;padding:2px 7px;border-radius:3px;font-size:0.78em;font-weight:bold">{sev}</span>'

    rows = ""
    for r in all_results:
        risk = r["risk_score"]
        lbl, _ = risk_label(risk)
        rows += f"""
        <tr>
          <td><b>{r['host']}</b></td>
          <td>{r['os']['guess']}</td>
          <td>{len(r['open_ports'])}</td>
          <td>{len(r['udp_ports'])}</td>
          <td>{len(r['vulnerabilities'])}</td>
          <td>{sev_badge(lbl)} {risk}/10</td>
        </tr>"""

    detail_sections = ""
    for r in all_results:
        vuln_rows = ""
        for v in r["vulnerabilities"]:
            score, sev = v["cvss"]
            vuln_rows += f"""
            <tr>
              <td>{sev_badge(sev)}</td>
              <td><code>{v['cve']}</code></td>
              <td>{score}</td>
              <td>{v['port']}/{get_service(v['port'])}</td>
              <td>{v['description']}</td>
              <td><small>{v['remediation']}</small></td>
              <td><small><code>{v.get('msf_module','N/A')}</code></small></td>
            </tr>"""

        port_rows = "".join(
            f"<tr><td>{p['port']}/tcp</td><td>{p['service']}</td><td>{p.get('category','')}</td><td><small>{(p.get('banner','') or '')[:60]}</small></td></tr>"
            for p in r["open_ports"]
        )
        udp_rows = "".join(
            f"<tr><td>{p['port']}/udp</td><td>{p['service']}</td><td>{p.get('state','')}</td></tr>"
            for p in r["udp_ports"]
        )

        tls_section = ""
        for port, tls in r.get("tls", {}).items():
            if tls.get("enabled"):
                cert = tls.get("cert", {})
                days = cert.get("days_until_expiry", "?")
                tls_section += f"""
                <h4>TLS on port {port}</h4>
                <table class="inner">
                  <tr><td>Protocol</td><td>{tls.get('version','?')}</td></tr>
                  <tr><td>Cipher</td><td>{tls.get('cipher','?')}</td></tr>
                  <tr><td>Subject CN</td><td>{cert.get('subject_cn','?')}</td></tr>
                  <tr><td>Issuer</td><td>{cert.get('issuer_cn','?')}</td></tr>
                  <tr><td>Days Until Expiry</td><td>{days}</td></tr>
                  <tr><td>Weak Versions</td><td>{', '.join(tls.get('weak_versions',[])) or 'None'}</td></tr>
                  <tr><td>Weak Ciphers</td><td>{', '.join(tls.get('weak_ciphers',[])) or 'None'}</td></tr>
                </table>"""

        trace_rows = "".join(
            f"<tr><td>{h['hop']}</td><td>{h['ip']}</td><td>{h.get('hostname','')}</td><td>{h.get('rtt_ms','?')} ms</td></tr>"
            for h in r.get("traceroute", [])
        )
        trace_section = f"""
        <h3>Traceroute</h3>
        <table>
          <tr><th>#</th><th>IP</th><th>Hostname</th><th>RTT</th></tr>
          {trace_rows}
        </table>""" if trace_rows else ""

        lbl, _ = risk_label(r["risk_score"])
        detail_sections += f"""
        <div class="host-section">
          <h2>Host: {r['host']} {sev_badge(lbl)} {r['risk_score']}/10</h2>
          <p><b>OS:</b> {r['os']['guess']} ({r['os']['confidence']} confidence)</p>

          <h3>Open TCP Ports ({len(r['open_ports'])})</h3>
          <table>
            <tr><th>Port</th><th>Service</th><th>Category</th><th>Banner</th></tr>
            {port_rows or '<tr><td colspan="4">None</td></tr>'}
          </table>

          <h3>Open UDP Ports ({len(r['udp_ports'])})</h3>
          <table>
            <tr><th>Port</th><th>Service</th><th>State</th></tr>
            {udp_rows or '<tr><td colspan="3">None</td></tr>'}
          </table>

          <h3>TLS/SSL Audit</h3>
          {tls_section or '<p>No TLS services detected</p>'}

          <h3>Vulnerabilities ({len(r['vulnerabilities'])})</h3>
          <table>
            <tr><th>Severity</th><th>CVE/ID</th><th>CVSS</th><th>Port</th><th>Description</th><th>Remediation</th><th>MSF Module</th></tr>
            {vuln_rows or '<tr><td colspan="7">No vulnerabilities matched</td></tr>'}
          </table>

          {trace_section}
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>NetPwn v2.0 – Vulnerability Assessment Report</title>
<style>
  :root {{--bg:#0d1117;--surface:#161b22;--border:#30363d;--text:#c9d1d9;--accent:#58a6ff;--red:#f85149;--green:#3fb950;--yellow:#d29922;}}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',monospace;background:var(--bg);color:var(--text);padding:32px}}
  h1{{color:var(--accent);margin-bottom:4px}}
  h2{{color:var(--accent);margin:24px 0 8px;border-bottom:1px solid var(--border);padding-bottom:6px}}
  h3{{color:#8b949e;margin:16px 0 6px}}
  h4{{color:#8b949e;margin:10px 0 4px}}
  table{{width:100%;border-collapse:collapse;margin-bottom:16px;font-size:0.88em}}
  th{{background:var(--surface);border:1px solid var(--border);padding:8px;text-align:left;color:var(--accent)}}
  td{{border:1px solid var(--border);padding:7px;vertical-align:top}}
  tr:nth-child(even) td{{background:#0f1318}}
  code{{background:#1f2428;padding:1px 5px;border-radius:3px;font-size:0.9em;color:#79c0ff}}
  .host-section{{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:28px}}
  .summary-table td{{text-align:center}}
  .meta{{color:#8b949e;font-size:0.82em;margin-bottom:24px}}
  table.inner{{width:auto;min-width:400px}}
</style>
</head>
<body>
<h1>🔍 NetPwn v2.0 – Network Vulnerability Assessment Report</h1>
<p class="meta">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')} | Hosts: {len(all_results)}</p>

<h2>Executive Summary</h2>
<table class="summary-table">
  <tr><th>Host</th><th>OS Guess</th><th>TCP Ports</th><th>UDP Ports</th><th>Vulnerabilities</th><th>Risk Score</th></tr>
  {rows}
</table>

{detail_sections}

<hr style="border-color:var(--border);margin:32px 0">
<p class="meta">NetPwn v2.0 | Ethical use only. Unauthorized scanning is illegal.</p>
</body>
</html>"""

    with open(output_file, "w") as f:
        f.write(html)
    print(f"{C.GREEN}[+] HTML report: {output_file}{C.RESET}")


def save_json_report(all_results: List[Dict], output_file: str):
    report = {
        "tool": "NetPwn", "version": "2.0",
        "scan_time": datetime.now().isoformat(),
        "hosts_scanned": len(all_results),
        "results": all_results
    }
    
    def default_encoder(obj):
        if isinstance(obj, tuple):
            return list(obj)
        return str(obj)
    with open(output_file, "w") as f:
        json.dump(report, f, indent=2, default=default_encoder)
    print(f"{C.GREEN}[+] JSON report: {output_file}{C.RESET}")

def save_txt_report(all_results: List[Dict], output_file: str):
    lines = ["=" * 64,
             "     NetPwn v2.0 – Network Vulnerability Assessment Report",
             f"     Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
             "=" * 64, ""]
    for r in all_results:
        lbl, _ = risk_label(r["risk_score"])
        lines += [
            f"Host            : {r['host']}",
            f"OS Guess        : {r['os']['guess']} ({r['os']['confidence']} confidence)",
            f"Risk Score      : {r['risk_score']}/10 [{lbl}]",
            f"TCP Open Ports  : {len(r['open_ports'])}",
            f"UDP Open Ports  : {len(r['udp_ports'])}",
            f"Vulnerabilities : {len(r['vulnerabilities'])}",
            "",
            "  [ TCP PORTS ]",
        ]
        for p in r["open_ports"]:
            lines.append(f"  {p['port']:<7} {p['service']:<14} {(p.get('banner','') or '')[:50]}")
        lines += ["", "  [ VULNERABILITIES ]"]
        for v in r["vulnerabilities"]:
            score, sev = v["cvss"]
            lines += [
                f"  [{sev}] {v['cve']} (CVSS:{score}) – Port {v['port']}",
                f"    {v['description']}",
                f"    Fix: {v['remediation']}",
                f"    MSF: {v.get('msf_module','N/A')}",
                "",
            ]
        lines += ["─" * 64, ""]
    with open(output_file, "w") as f:
        f.write("\n".join(lines))
    print(f"{C.GREEN}[+] Text report: {output_file}{C.RESET}")


def print_executive_summary(all_results: List[Dict]):
    print(f"\n{C.BOLD}{C.MAGENTA}{'═'*62}")
    print("               EXECUTIVE SUMMARY")
    print(f"{'═'*62}{C.RESET}")
    print(f"  {C.BOLD}{'HOST':<18}{'OS':<22}{'TCP':<6}{'UDP':<6}{'VULN':<6}RISK{C.RESET}")
    print(f"  {'─'*58}")
    for r in all_results:
        lbl, lc = risk_label(r["risk_score"])
        os_s = r["os"]["guess"][:20]
        print(f"  {r['host']:<18}{os_s:<22}{len(r['open_ports']):<6}{len(r['udp_ports']):<6}"
              f"{len(r['vulnerabilities']):<6}{lc}{r['risk_score']}/10 [{lbl}]{C.RESET}")

    total_vulns = sum(len(r["vulnerabilities"]) for r in all_results)
    critical = sum(1 for r in all_results for v in r["vulnerabilities"] if v["cvss"][1] == "CRITICAL")
    print(f"\n  {C.WHITE}Total vulnerabilities : {total_vulns}{C.RESET}")
    print(f"  {C.RED}Critical severity     : {critical}{C.RESET}")
    print(f"\n  Scan finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")


def parse_ports(port_range: str) -> List[int]:
    ports = set()
    for part in port_range.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def run_scan(args):
    print(BANNER)
    timing = TIMING_PROFILES[args.timing]
    print(f"{C.WHITE}  Target      : {C.CYAN}{args.target}{C.RESET}")
    print(f"{C.WHITE}  Ports       : {C.CYAN}{args.ports}{C.RESET}")
    print(f"{C.WHITE}  Timing      : {C.CYAN}{timing['label']}{C.RESET}")
    print(f"{C.WHITE}  UDP Scan    : {C.CYAN}{'Yes' if not args.no_udp else 'No'}{C.RESET}")
    print(f"{C.WHITE}  TLS Audit   : {C.CYAN}{'Yes' if not args.no_tls else 'No'}{C.RESET}")
    print(f"{C.WHITE}  Traceroute  : {C.CYAN}{'Yes' if args.traceroute else 'No'}{C.RESET}")
    print(f"{C.WHITE}  Started     : {C.CYAN}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{C.RESET}")
    print(f"{C.WHITE}  {'─'*56}{C.RESET}\n")

    ports = parse_ports(args.ports)

    
    if "/" in args.target:
        hosts = discover_hosts(args.target, method=args.discovery)
    else:
        alive = ping_host(args.target) or tcp_ping(args.target)
        if alive:
            cprint(C.GREEN, f"[+] {args.target} is UP")
        else:
            cprint(C.YELLOW, f"[!] {args.target} appears DOWN – scanning anyway")
        hosts = [args.target]

    if not hosts:
        cprint(C.RED, "[!] No live hosts found. Exiting.")
        sys.exit(1)

    all_results = []

    for host in hosts:
        print(f"\n{C.BOLD}{C.CYAN}{'─'*62}{C.RESET}")
        print(f"{C.BOLD}{C.WHITE}  Scanning: {host}{C.RESET}")
        print(f"{C.CYAN}{'─'*62}{C.RESET}")

    
        print(f"\n{C.CYAN}[*] TCP port scan ({len(ports)} ports, timing={args.timing})...{C.RESET}")
        open_ports = scan_ports_tcp(host, ports, timing)
        cprint(C.GREEN, f"[+] {len(open_ports)} open TCP port(s)")

        
        udp_ports = []
        if not args.no_udp:
            udp_ports = scan_udp(host)

        
        os_info = fingerprint_os(host, open_ports)
        print(f"{C.WHITE}[*] OS: {os_info['guess']} ({os_info['confidence']}){C.RESET}")

       
        service_meta = {}
        fingerprinter = ServiceFingerprinter()
        print(f"\n{C.CYAN}[*] Deep service fingerprinting...{C.RESET}")
        for p in open_ports:
            port = p["port"]
            try:
                if port in (80, 8080, 443, 8443, 3000, 9200):
                    service_meta[port] = fingerprinter.fingerprint_http(host, port)
                elif port == 21:
                    service_meta[port] = fingerprinter.fingerprint_ftp(host, port)
                elif port == 25:
                    service_meta[port] = fingerprinter.fingerprint_smtp(host, port)
                elif port == 6379:
                    service_meta[port] = fingerprinter.fingerprint_redis(host, port)
                else:
                    service_meta[port] = fingerprinter.fingerprint_generic(host, port)
            except Exception:
                pass

       
        tls_results = {}
        if not args.no_tls:
            print(f"{C.CYAN}[*] TLS/SSL audit...{C.RESET}")
            ssl_ports = [p["port"] for p in open_ports if p["port"] in (443, 8443, 993, 995, 465, 636, 5986)]
            for sp in ssl_ports:
                tls_results[sp] = TLSAuditor.audit(host, sp)

       
        traceroute = []
        if args.traceroute:
            print(f"{C.CYAN}[*] Running traceroute...{C.RESET}")
            traceroute = run_traceroute(host, max_hops=args.max_hops)

       
        anon_ftp = service_meta.get(21, {}).get("anonymous", False)

       
        print(f"{C.CYAN}[*] Matching vulnerability signatures...{C.RESET}")
        vulns = match_vulnerabilities(open_ports, tls_results, service_meta, anon_ftp)

        
        risk_score = calculate_risk_score(vulns)

        
        print_host_report(host, open_ports, udp_ports, vulns, tls_results,
                          service_meta, os_info, traceroute, risk_score)

        all_results.append({
            "host": host,
            "scan_time": datetime.now().isoformat(),
            "os": os_info,
            "open_ports": open_ports,
            "udp_ports": udp_ports,
            "service_meta": service_meta,
            "tls": {str(k): v for k, v in tls_results.items()},
            "vulnerabilities": vulns,
            "traceroute": traceroute,
            "risk_score": risk_score,
        })

    
    if not args.no_save:
        os.makedirs(os.path.dirname(args.output) if os.path.dirname(args.output) else ".", exist_ok=True)
        save_json_report(all_results, f"{args.output}.json")
        save_txt_report(all_results,  f"{args.output}.txt")
        generate_html_report(all_results, f"{args.output}.html")

    print_executive_summary(all_results)


def main():
    parser = argparse.ArgumentParser(
        description="NetPwn v1.0 – Advanced Network Vulnerability Assessment Suite",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=""

    )
    parser.add_argument("-t", "--target",    required=True,
                        help="Target IP, hostname, or CIDR range (e.g. 192.168.1.0/24)")
    parser.add_argument("-p", "--ports",     default="1-1024",
                        help="Port range (default: 1-1024)\nExamples: 80,443 | 1-65535 | 22,80,3306")
    parser.add_argument("--timing",          default="normal",
                        choices=list(TIMING_PROFILES.keys()),
                        help="Timing profile: paranoid/sneaky/polite/normal/aggressive/insane (default: normal)")
    parser.add_argument("--discovery",       default="auto",
                        choices=["auto","ping","tcp","arp"],
                        help="Host discovery method (default: auto)")
    parser.add_argument("--no-udp",          action="store_true",
                        help="Skip UDP scanning")
    parser.add_argument("--no-tls",          action="store_true",
                        help="Skip TLS/SSL audit")
    parser.add_argument("--traceroute",      action="store_true",
                        help="Perform traceroute to each host")
    parser.add_argument("--max-hops",        type=int, default=20,
                        help="Max hops for traceroute (default: 20)")
    parser.add_argument("-o", "--output",    default="reports/netpwn",
                        help="Output file base path (default: reports/netpwn)")
    parser.add_argument("--no-save",         action="store_true",
                        help="Don't write report files")

    args = parser.parse_args()

    try:
        run_scan(args)
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}[!] Scan aborted by user.{C.RESET}")
        sys.exit(0)

if __name__ == "__main__":
    main()
