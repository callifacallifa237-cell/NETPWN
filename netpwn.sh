#!/bin/bash
# ════════════════════════════════════════════════════════════════
#  NetPwn v1.0 – Advanced Network Assessment Suite
#  Setup, Dependency Manager & Interactive Launcher
#  Requires: Kali Linux (or Debian/Ubuntu-based distro)
#  Run as: sudo bash netpwn.sh
# ════════════════════════════════════════════════════════════════

set -euo pipefail
IFS=$'\n\t'


RED='\033[0;31m';  LRED='\033[1;31m'
GREEN='\033[0;32m'; LGRN='\033[1;32m'
YELLOW='\033[1;33m'; CYAN='\033[0;36m'; LCYN='\033[1;36m'
WHITE='\033[1;37m'; GRAY='\033[0;90m'; MAGENTA='\033[0;35m'
BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_SCRIPT="$SCRIPT_DIR/netpwn.py"
REPORTS_DIR="$SCRIPT_DIR/reports"
LOG_DIR="$SCRIPT_DIR/logs"
LOG_FILE="$LOG_DIR/netpwn_$(date +%Y%m%d).log"
VERSION="2.0"


log() {
    local level="$1"; shift
    local msg="$*"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $msg" >> "$LOG_FILE" 2>/dev/null || true
}

info()    { echo -e "${CYAN}[*]${RESET} $*";  log "INFO"  "$*"; }
success() { echo -e "${LGRN}[+]${RESET} $*";  log "OK"    "$*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; log "WARN"  "$*"; }
err()     { echo -e "${LRED}[!]${RESET} $*";  log "ERROR" "$*"; }
section() { echo -e "\n${WHITE}${BOLD}  $*${RESET}"; }


show_banner() {
    clear
    echo -e "${LRED}${BOLD}"
    cat << 'EOF'
 ███╗   ██╗███████╗████████╗██████╗ ██╗    ██╗███╗   ██╗
 ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║    ██║████╗  ██║
 ██╔██╗ ██║█████╗     ██║   ██████╔╝██║ █╗ ██║██╔██╗ ██║
 ██║╚██╗██║██╔══╝     ██║   ██╔═══╝ ██║███╗██║██║╚██╗██║
 ██║ ╚████║███████╗   ██║   ██║     ╚███╔███╔╝██║ ╚████║
 ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝
EOF
    echo -e "${RESET}"
    echo -e "${YELLOW}  v${VERSION} ─ Advanced Network Vulnerability Assessment Suite${RESET}"
    echo -e "${GRAY}  Master-Level Cybersecurity Research Tool | Ethical Use Only${RESET}"
    echo -e "${WHITE}  $(printf '─%.0s' {1..58})${RESET}"
    echo ""

    
    if [[ $EUID -eq 0 ]]; then
        echo -e "  ${LGRN}[ROOT]${RESET}  Full capabilities available (SYN scan, ARP, OS detect)"
    else
        echo -e "  ${YELLOW}[USER]${RESET}  Some features require root: ${DIM}sudo bash netpwn.sh${RESET}"
    fi

   
    if command -v python3 &>/dev/null; then
        local pyver; pyver=$(python3 --version 2>&1 | awk '{print $2}')
        echo -e "  ${CYAN}[PYTHON]${RESET} $pyver"
    fi
    echo ""
}


show_disclaimer() {
    echo -e "${LRED}${BOLD}"
    echo "  ╔═══════════════════════════════════════════════════════╗"
    echo "  ║                ⚠  LEGAL DISCLAIMER ⚠                  ║"
    echo "  ║                                                       ║"
    echo "  ║  NetPwn is for AUTHORIZED penetration testing and     ║"
    echo "  ║  EDUCATIONAL research ONLY.                           ║"
    echo "  ║                                                       ║"
    echo "  ║  Only scan systems you OWN or have WRITTEN            ║"
    echo "  ║  PERMISSION to test. Authors accept no liability.     ║"
    echo "  ╚═══════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
    echo -ne "${YELLOW}  I accept full legal responsibility [yes/NO]: ${RESET}"
    read -r answer
    if [[ "$answer" != "yes" && "$answer" != "YES" ]]; then
        echo -e "${LRED}[!] You must type 'yes' to proceed. Exiting.${RESET}"
        exit 1
    fi
    log "LEGAL" "Disclaimer accepted by user at $(date)"
}


REQUIRED_APT=(python3 python3-pip nmap traceroute netcat-openbsd whois dnsutils iputils-ping arp-scan arping)
REQUIRED_PY3=() 

check_and_install_deps() {
    section "Checking Dependencies"
    echo ""
    local missing_apt=()

    for pkg in "${REQUIRED_APT[@]}"; do
        if command -v "$pkg" &>/dev/null || dpkg -l "$pkg" &>/dev/null 2>&1; then
            echo -e "  ${LGRN}✓${RESET} ${pkg}"
        else
            echo -e "  ${YELLOW}✗${RESET} ${pkg} ${GRAY}(missing)${RESET}"
            missing_apt+=("$pkg")
        fi
    done

    if [[ ${#missing_apt[@]} -gt 0 ]]; then
        echo ""
        warn "Installing missing packages: ${missing_apt[*]}"
        if [[ $EUID -eq 0 ]]; then
            apt-get update -qq
            for pkg in "${missing_apt[@]}"; do
                if apt-get install -y -qq "$pkg" 2>/dev/null; then
                    success "Installed: $pkg"
                else
                    warn "Could not install: $pkg (continuing)"
                fi
            done
        else
            err "Run as root to auto-install: sudo bash netpwn.sh"
        fi
    else
        echo ""
        success "All dependencies satisfied"
    fi
}


setup_environment() {
    mkdir -p "$REPORTS_DIR" "$LOG_DIR"
    touch "$LOG_FILE"
    
    if [[ -f "$PYTHON_SCRIPT" ]]; then
        chmod +x "$PYTHON_SCRIPT"
    fi
    success "Workspace: $SCRIPT_DIR"
    success "Reports  : $REPORTS_DIR"
    success "Logs     : $LOG_DIR"
}


get_target() {
    echo ""
    echo -ne "  ${CYAN}Target (IP / CIDR / hostname): ${RESET}"
    read -r TARGET

    if [[ -z "$TARGET" ]]; then
        err "No target provided."
        return 1
    fi

    
    if [[ ! "$TARGET" =~ ^[0-9a-zA-Z.:/_-]+$ ]]; then
        warn "Unusual target format – double-check before proceeding"
    fi

    log "TARGET" "$TARGET"
    return 0
}

get_port_range() {
    echo -ne "  ${CYAN}Port range [default: 1-1024]: ${RESET}"
    read -r PORT_RANGE
    PORT_RANGE="${PORT_RANGE:-1-1024}"
}

select_timing() {
    echo ""
    echo -e "  ${BOLD}${WHITE}Timing Profile:${RESET}"
    echo -e "  ${GRAY}1)${RESET} paranoid   ${DIM}T0 – IDS evasion, 1 thread, 5s delay${RESET}"
    echo -e "  ${GRAY}2)${RESET} sneaky     ${DIM}T1 – Low and slow, 5 threads${RESET}"
    echo -e "  ${GRAY}3)${RESET} polite     ${DIM}T2 – Reduced bandwidth, 15 threads${RESET}"
    echo -e "  ${LGRN}4)${RESET} normal     ${DIM}T3 – Default, 100 threads${RESET} (default)"
    echo -e "  ${GRAY}5)${RESET} aggressive ${DIM}T4 – Fast LAN, 200 threads${RESET}"
    echo -e "  ${YELLOW}6)${RESET} insane     ${DIM}T5 – May drop packets, 500 threads${RESET}"
    echo -ne "  ${CYAN}Choice [1-6, default=4]: ${RESET}"
    read -r tchoice
    case "$tchoice" in
        1) TIMING="paranoid"   ;;
        2) TIMING="sneaky"     ;;
        3) TIMING="polite"     ;;
        5) TIMING="aggressive" ;;
        6) TIMING="insane"     ;;
        *) TIMING="normal"     ;;
    esac
}


run_python() {
    local extra_args="$*"
    local ts; ts=$(date +%Y%m%d_%H%M%S)
    local out="$REPORTS_DIR/scan_${TARGET/\//_}_$ts"

    echo -e "\n${CYAN}[*] Launching NetPwn v2.0 Python scanner...${RESET}"
    echo -e "${GRAY}    python3 $PYTHON_SCRIPT -t $TARGET -p $PORT_RANGE --timing $TIMING -o $out $extra_args${RESET}\n"

    log "SCAN" "python3 netpwn.py -t $TARGET -p $PORT_RANGE --timing $TIMING -o $out $extra_args"

    python3 "$PYTHON_SCRIPT" \
        -t "$TARGET" \
        -p "$PORT_RANGE" \
        --timing "$TIMING" \
        -o "$out" \
        $extra_args

    echo ""
    echo -e "${LGRN}[+] Reports saved:${RESET}"
    for ext in txt json html; do
        [[ -f "${out}.${ext}" ]] && echo -e "    ${CYAN}${out}.${ext}${RESET}"
    done
}


run_nmap() {
    local scan_type="$1"
    local ts; ts=$(date +%Y%m%d_%H%M%S)
    local base="$REPORTS_DIR/nmap_${TARGET/\//_}_${scan_type}_$ts"

    echo -e "\n${CYAN}[*] Nmap ${scan_type} scan on ${TARGET}...${RESET}"

    declare -A NMAP_PROFILES=(
        ["quick"]="nmap -sS -F --open -T4 --reason"
        ["service"]="-sV -sC --open -T4 --version-intensity 7"
        ["vuln"]="nmap -sV --script vuln,auth,safe --open -T4"
        ["full"]="nmap -sS -p- --open -T4 --min-rate 1000"
        ["stealth"]="nmap -sS -O --open -T2 --data-length 24"
        ["udp"]="nmap -sU --top-ports 200 --open -T4"
        ["smb"]="nmap -p 139,445 --script smb-vuln* --open -T4"
        ["http"]="nmap -p 80,443,8080,8443 --script http-headers,http-methods,http-title,http-auth-finder --open -T4"
        ["db"]="nmap -p 1433,1521,3306,5432,6379,9200,27017 --script *-info,*-databases --open -T4"
        ["auth"]="nmap -p 21,22,23,25,110,143 --script *-brute,*-auth --open -T4"
    )

    local nmap_cmd="${NMAP_PROFILES[$scan_type]:-nmap -sV --open -T4}"
    local full_cmd="nmap $nmap_cmd $TARGET -oN ${base}.txt -oX ${base}.xml"

    echo -e "${GRAY}    $full_cmd${RESET}\n"
    log "NMAP" "$full_cmd"

    if eval "$full_cmd"; then
        success "Nmap report: ${base}.txt"
        echo ""
        
        if [[ -f "${base}.txt" ]]; then
            grep -E "^[0-9]+/(tcp|udp)" "${base}.txt" | while read -r line; do
                echo -e "  ${LGRN}[PORT]${RESET} $line"
            done
        fi
    else
        err "Nmap scan failed or was interrupted"
    fi
}

run_recon() {
    echo -e "\n${CYAN}[*] Quick OSINT/Recon on: ${TARGET}${RESET}"
    echo -e "${WHITE}$(printf '─%.0s' {1..50})${RESET}"

   
    echo -e "\n${YELLOW}[Reverse DNS]${RESET}"
    host "$TARGET" 2>/dev/null || echo "  No PTR record"

    
    if [[ "$TARGET" =~ [a-zA-Z] ]]; then
        echo -e "\n${YELLOW}[DNS Records]${RESET}"
        for rec in A AAAA MX NS TXT; do
            result=$(dig +short "$TARGET" "$rec" 2>/dev/null)
            [[ -n "$result" ]] && echo -e "  ${CYAN}$rec${RESET}  $result"
        done
    fi

   
    echo -e "\n${YELLOW}[WHOIS — key fields]${RESET}"
    if command -v whois &>/dev/null; then
        whois "$TARGET" 2>/dev/null | grep -iE "^(netname|country|orgname|org:|cidr|netrange|abuse|descr|inetnum|org-name)" | head -15 | \
            while read -r line; do echo "  $line"; done
    else
        warn "whois not installed"
    fi

    
    echo -e "\n${YELLOW}[Traceroute (first 10 hops)]${RESET}"
    if command -v traceroute &>/dev/null; then
        traceroute -m 10 -w 1 -q 1 "$TARGET" 2>/dev/null | tail -n +2 | \
            while read -r line; do echo -e "  ${GRAY}$line${RESET}"; done
    else
        warn "traceroute not installed"
    fi

    log "RECON" "Target: $TARGET"
}


view_reports() {
    echo -e "\n${CYAN}[*] Saved Reports in: ${REPORTS_DIR}${RESET}"
    echo -e "${WHITE}$(printf '─%.0s' {1..50})${RESET}"

    if ! ls "$REPORTS_DIR"/ &>/dev/null || [[ -z "$(ls -A "$REPORTS_DIR")" ]]; then
        warn "No reports found yet."
        return
    fi

    
    local count=0
    while IFS= read -r -d '' file; do
        count=$((count+1))
        local size; size=$(du -sh "$file" 2>/dev/null | awk '{print $1}')
        local name; name=$(basename "$file")
        local ts; ts=$(stat -c %y "$file" 2>/dev/null | cut -d. -f1)
        printf "  ${CYAN}%3d)${RESET} %-48s ${GRAY}%6s  %s${RESET}\n" "$count" "$name" "$size" "$ts"
    done < <(find "$REPORTS_DIR" -maxdepth 1 -type f -name "*.txt" -o -name "*.html" -o -name "*.json" 2>/dev/null | sort -t_ -k3 -r | head -20 | tr '\n' '\0')

    if [[ $count -eq 0 ]]; then
        warn "No report files found."
        return
    fi

    echo ""
    echo -ne "${CYAN}  Enter filename to view (or Enter to skip): ${RESET}"
    read -r rfile
    if [[ -n "$rfile" ]]; then
        local full_path="$REPORTS_DIR/$rfile"
        if [[ -f "$full_path" ]]; then
            if [[ "$rfile" == *.html ]]; then
                
                for cmd in xdg-open firefox chromium-browser; do
                    if command -v "$cmd" &>/dev/null; then
                        $cmd "$full_path" &>/dev/null &
                        success "Opened in browser: $rfile"
                        return
                    fi
                done
                warn "No browser found. Viewing raw HTML:"
            fi
            less -R "$full_path"
        else
            err "File not found: $full_path"
        fi
    fi
}


run_custom_nmap() {
    get_target || return
    echo -ne "${CYAN}  Custom nmap flags (e.g. -sV -p 80,443 --script http-title): ${RESET}"
    read -r custom_flags
    local ts; ts=$(date +%Y%m%d_%H%M%S)
    local base="$REPORTS_DIR/custom_${TARGET/\//_}_$ts"
    echo -e "${GRAY}  Running: nmap $custom_flags $TARGET -oN ${base}.txt${RESET}"
    log "CUSTOM_NMAP" "nmap $custom_flags $TARGET"
    nmap $custom_flags "$TARGET" -oN "${base}.txt"
    success "Saved: ${base}.txt"
}


show_interfaces() {
    echo -e "\n${YELLOW}[Network Interfaces]${RESET}"
    ip -brief addr show 2>/dev/null || ifconfig 2>/dev/null | grep -E "(inet |ether)"
    echo -e "\n${YELLOW}[Default Gateway & Routes]${RESET}"
    ip route show 2>/dev/null || route -n 2>/dev/null
    echo -e "\n${YELLOW}[ARP Cache]${RESET}"
    arp -n 2>/dev/null | head -20
}


show_menu() {
    echo -e "${WHITE}${BOLD}  ╔══════════════════════════════════════════════════════╗${RESET}"
    echo -e "${WHITE}${BOLD}  ║              NETPWN v2.0 – MAIN MENU                ║${RESET}"
    echo -e "${WHITE}${BOLD}  ╠══════════════════════════════════════════════════════╣${RESET}"
    echo -e "  ║ ${CYAN}${BOLD}── NETPWN PYTHON ENGINE ──────────────────────────${RESET} ║"
    echo -e "  ║  ${LGRN}1)${RESET} Standard Scan       ${DIM}TCP + UDP + TLS + Vulns${RESET}         ║"
    echo -e "  ║  ${LGRN}2)${RESET} Full Port Scan       ${DIM}1-65535 + all modules${RESET}          ║"
    echo -e "  ║  ${LGRN}3)${RESET} Stealth/Evasion Scan ${DIM}Paranoid/Sneaky timing${RESET}         ║"
    echo -e "  ║  ${LGRN}4)${RESET} Targeted Service Scan${DIM}Custom ports + deep FP${RESET}         ║"
    echo -e "  ║  ${LGRN}5)${RESET} Scan + Traceroute    ${DIM}Topology mapping${RESET}               ║"
    echo -e "  ║ ${CYAN}${BOLD}── NMAP INTEGRATION ──────────────────────────────${RESET} ║"
    echo -e "  ║  ${YELLOW}6)${RESET} Nmap Quick SYN       ${DIM}Top ports, fast T4${RESET}            ║"
    echo -e "  ║  ${YELLOW}7)${RESET} Nmap Service Scan    ${DIM}-sV -sC banners${RESET}               ║"
    echo -e "  ║  ${YELLOW}8)${RESET} Nmap Vuln NSE        ${DIM}--script vuln,auth,safe${RESET}       ║"
    echo -e "  ║  ${YELLOW}9)${RESET} Nmap SMB Audit       ${DIM}EternalBlue, MS17-010${RESET}         ║"
    echo -e "  ║  ${YELLOW}10)${RESET} Nmap HTTP Audit     ${DIM}Headers, methods, title${RESET}       ║"
    echo -e "  ║  ${YELLOW}11)${RESET} Nmap DB Audit       ${DIM}MySQL/Mongo/Redis/Elastic${RESET}     ║"
    echo -e "  ║  ${YELLOW}12)${RESET} Nmap Full UDP        ${DIM}Top 200 UDP ports${RESET}            ║"
    echo -e "  ║  ${YELLOW}13)${RESET} Nmap Custom Flags    ${DIM}Enter your own args${RESET}          ║"
    echo -e "  ║ ${CYAN}${BOLD}── RECON & UTILITIES ─────────────────────────────${RESET} ║"
    echo -e "  ║  ${MAGENTA}14)${RESET} OSINT Recon          ${DIM}WHOIS + DNS + Traceroute${RESET}    ║"
    echo -e "  ║  ${MAGENTA}15)${RESET} Network Interfaces   ${DIM}Local routes + ARP cache${RESET}   ║"
    echo -e "  ║  ${MAGENTA}16)${RESET} View Reports         ${DIM}Browse saved scan output${RESET}    ║"
    echo -e "  ║  ${MAGENTA}17)${RESET} Check Dependencies   ${DIM}Re-run dependency check${RESET}    ║"
    echo -e "${WHITE}${BOLD}  ╠══════════════════════════════════════════════════════╣${RESET}"
    echo -e "  ║  ${RED}0)${RESET}  Exit                                              ║"
    echo -e "${WHITE}${BOLD}  ╚══════════════════════════════════════════════════════╝${RESET}"
    echo ""
    echo -ne "  ${CYAN}Select option: ${RESET}"
}


pause() {
    echo ""
    echo -ne "${GRAY}  Press Enter to return to menu...${RESET}"
    read -r
    show_banner
}


main() {
   
    mkdir -p "$LOG_DIR"
    touch "$LOG_FILE" 2>/dev/null || true

    show_banner
    show_disclaimer
    show_banner
    check_and_install_deps
    setup_environment

    echo ""
    info "NetPwn v${VERSION} ready. $(date '+%Y-%m-%d %H:%M:%S')"

    sleep 0.5

    while true; do
        echo ""
        show_menu
        read -r choice

        case "$choice" in
            
            1)
                get_target  || { pause; continue; }
                get_port_range
                select_timing
                run_python
                ;;
            2)
                get_target  || { pause; continue; }
                PORT_RANGE="1-65535"
                select_timing
                run_python "--traceroute"
                warn "Full scan may take 15–60 min depending on timing profile"
                ;;
            3)
                get_target  || { pause; continue; }
                get_port_range
                echo -ne "  ${CYAN}Timing [paranoid/sneaky, default=sneaky]: ${RESET}"
                read -r st
                TIMING="${st:-sneaky}"
                run_python "--no-udp"
                ;;
            4)
                get_target  || { pause; continue; }
                get_port_range
                select_timing
                run_python "--no-udp --no-tls"
                ;;
            5)
                get_target  || { pause; continue; }
                get_port_range
                select_timing
                run_python "--traceroute"
                ;;
           
            6|7|8|9|10|11|12)
                get_target || { pause; continue; }
                PORT_RANGE="0"
                TIMING="normal"
                scan_map=( [6]="quick" [7]="service" [8]="vuln" [9]="smb" [10]="http" [11]="db" [12]="udp" )
                run_nmap "${scan_map[$choice]}"
                ;;
            13)
                run_custom_nmap
                ;;
            
            14)
                get_target || { pause; continue; }
                PORT_RANGE="0"
                TIMING="normal"
                run_recon
                ;;
            15)
                show_interfaces
                ;;
            16)
                view_reports
                ;;
            17)
                check_and_install_deps
                ;;
            0)
                echo -e "\n${LGRN}[+] Exiting NetPwn. Stay ethical, stay legal.${RESET}\n"
                log "EXIT" "User exited NetPwn"
                exit 0
                ;;
            *)
                err "Invalid choice: $choice"
                ;;
        esac

        pause
    done
}

main "$@"
