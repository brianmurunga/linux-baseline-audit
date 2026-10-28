#!/usr/bin/env bash
# baseline_audit.sh - Linux baseline audit (v0.3.0)
#
# DEFAULT MODE is read-only in intent: it inspects the system and writes
# report files. It does not change configuration, install packages, refresh
# package metadata, restart services or touch the firewall.
#
# --with-lynis is DIFFERENT: it may install the 'lynis' package (and refresh
# package metadata if the install fails without it) and Lynis itself writes
# under /var/log. The report records when this mode was used.
#
# Support: Debian/Ubuntu = primary target. RHEL-family and Alpine code paths
# exist but are UNTESTED. See README.md for what was and was not validated.
#
# Reports contain sensitive data (usernames, IPs, services, paths, login
# history). Never commit or publish them unredacted.
#
# Run `baseline_audit.sh --help` for usage.

set -uo pipefail
export LC_ALL=C

VERSION="0.3.0"
SCHEMA_VERSION=2

# ------------------------------------------------------------------
# Globals (plain assignments only: sourcing this file has no side effects)
# ------------------------------------------------------------------
WITH_LYNIS=0
FULL_EVIDENCE=0
ALLOW_NONROOT=0
OUTDIR="./audit-reports"

SHADOW_FILE=/etc/shadow      # overridable by unit tests after sourcing
MOUNTS_FILE=/proc/mounts     # overridable by unit tests after sourcing

HOST="" STAMP="" RAND=""
DISTRO_ID="unknown" DISTRO_FAMILY="unknown" DISTRO_PRETTY="" SUPPORT_LEVEL="unsupported"
EVID="" FINAL_TXT="" FINAL_JSON="" LYNIS_FINAL=""
FINALIZED=0
SECTION_NO=0
LAST_RC=0 LAST_CLASS=ok
CAP_OUT="" CAP_RC=0 CAP_CLASS=ok

declare -a CLEAN_FILES=()
declare -a F_ID=() F_CAT=() F_SEV=() F_ST=() F_MSG=()

# ------------------------------------------------------------------
# Colour: only on a TTY, unless NO_COLOR is set or TERM=dumb
# ------------------------------------------------------------------
setup_colors() {
  if [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]] && [[ "${TERM:-dumb}" != "dumb" ]]; then
    C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
    C_RED=$'\033[31m';  C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_BLUE=$'\033[34m'
  else
    C_RESET="" C_BOLD="" C_DIM="" C_RED="" C_GREEN="" C_YELLOW="" C_BLUE=""
  fi
}
setup_colors

# ------------------------------------------------------------------
# Small utilities
# ------------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

join_by() {  # join_by SEP item...
  local sep=$1 out="" x
  shift
  for x in "$@"; do out+="${out:+$sep}$x"; done
  printf '%s' "$out"
}

sanitize() { printf '%s' "${1//[[:cntrl:]]/?}"; }   # neutralise control chars for terminal/text

usage() {
  cat <<'EOF'
Usage: baseline_audit.sh [OPTIONS]

Linux baseline audit. The default mode is read-only in intent: it inspects the
system and writes a text report and a JSON report. It does not change
configuration, install software, refresh package metadata, or restart services.

Options:
  --output-dir DIR   Where to write reports (default: ./audit-reports, created
                     with mode 0700; existing dirs must be owned by you and not
                     group/world-writable)
  --with-lynis       ALSO install Lynis if missing and run it. THIS MODIFIES THE
                     SYSTEM (package install, possible metadata refresh, logs
                     under /var/log). Not part of the default read-only audit.
  --full-evidence    Include process arguments and cron command bodies. These
                     may contain secrets; the default redacts them.
  --allow-nonroot    Run without root. Many checks will be incomplete.
  --version          Print the version and exit
  -h, --help         Show this help and exit

Exit status:
  0 audit completed and both reports written
  1 not running as root (without --allow-nonroot)
  2 usage error
  3 output location unsafe or not writable
  4 JSON report could not be written (text report may exist)
  5 text report could not be written

The exit status does not depend on the findings.
Reports contain usernames, IP addresses, login history, services and paths.
Review and redact before sharing. Nothing is uploaded or transmitted.
EOF
}

usage_error() { echo "baseline_audit.sh: $1" >&2; echo >&2; usage >&2; exit 2; }
die() { echo "baseline_audit.sh: $1" >&2; exit "${2:-1}"; }

parse_args() {
  while (( $# )); do
    case $1 in
      -h|--help)       usage; exit 0 ;;
      --version)       echo "baseline_audit.sh $VERSION"; exit 0 ;;
      --with-lynis)    WITH_LYNIS=1 ;;
      --full-evidence) FULL_EVIDENCE=1 ;;
      --allow-nonroot) ALLOW_NONROOT=1 ;;
      --output-dir)
        (( $# >= 2 )) || usage_error "--output-dir requires an argument"
        OUTDIR=$2; shift ;;
      --output-dir=*)  OUTDIR=${1#*=} ;;
      *)               usage_error "unknown option: $1" ;;
    esac
    shift
  done
  [[ -n $OUTDIR ]] || usage_error "--output-dir must not be empty"
}

# ------------------------------------------------------------------
# Safe output handling
# ------------------------------------------------------------------
cleanup() {
  local f
  for f in "${CLEAN_FILES[@]:-}"; do
    [[ -n $f ]] && rm -f -- "$f"
  done
}

# finalize_file SRC DST : move SRC to DST, never overwriting an existing DST
# (including a symlink). Uses a hard link as an atomic no-clobber primitive.
finalize_file() {
  local src=$1 dst=$2
  if ln -- "$src" "$dst" 2>/dev/null; then
    rm -f -- "$src"
    return 0
  fi
  [[ -e $dst || -L $dst ]] && return 1
  mv -n -- "$src" "$dst" 2>/dev/null || return 1
  [[ ! -e $src ]]
}

prepare_output() {
  local created=0 st ouid omode
  if [[ -L $OUTDIR ]]; then die "output directory is a symlink: $OUTDIR" 3; fi
  if [[ -e $OUTDIR ]]; then
    [[ -d $OUTDIR ]] || die "output path exists and is not a directory: $OUTDIR" 3
  else
    mkdir -m 700 -- "$OUTDIR" 2>/dev/null || die "cannot create output directory: $OUTDIR" 3
    created=1
  fi
  st=$(stat -c '%u %a' -- "$OUTDIR" 2>/dev/null) || die "cannot stat output directory: $OUTDIR" 3
  ouid=${st% *}; omode=${st#* }
  [[ $ouid == "$(id -u)" ]] \
    || die "output directory is owned by uid ${ouid}, not the current user: $OUTDIR" 3
  (( (8#$omode & 8#022) == 0 )) \
    || die "output directory is group/world-writable (mode ${omode}): $OUTDIR" 3
  OUTDIR=$(cd -- "$OUTDIR" && pwd -P) || die "cannot resolve output directory" 3

  # A freshly created dir ignores everything, so reports cannot be committed by accident.
  if (( created )); then printf '*\n' >"$OUTDIR/.gitignore"; fi

  local base="baseline-${HOST}-${STAMP}-${RAND}"
  FINAL_TXT="$OUTDIR/${base}.txt"
  FINAL_JSON="$OUTDIR/${base}.json"
  EVID=$(mktemp "$OUTDIR/.partial-evidence-XXXXXX") || die "cannot create temporary file in $OUTDIR" 3
  CLEAN_FILES+=("$EVID")

  # Warn if the directory sits inside a git work tree that does not ignore it.
  if have git; then
    local inside ignored_rc
    inside=$(git -C "$OUTDIR" rev-parse --is-inside-work-tree 2>/dev/null || true)
    if [[ $inside == true ]]; then
      git -C "$OUTDIR" check-ignore -q -- "$OUTDIR/${base}.txt" 2>/dev/null
      ignored_rc=$?
      if (( ignored_rc == 1 )); then
        echo "WARNING: $OUTDIR is inside a git work tree and reports are NOT ignored. Add it to .gitignore." >&2
      elif (( ignored_rc > 1 )); then
        echo "NOTE: could not verify whether $OUTDIR is ignored by git." >&2
      fi
    fi
  fi
}

# ------------------------------------------------------------------
# Evidence and check execution helpers
# ------------------------------------------------------------------
classify_result() {  # rc output -> ok | not_found | denied | nonzero
  local rc=$1 out=$2
  if (( rc == 0 )); then echo ok
  elif (( rc == 127 )); then echo not_found
  elif [[ $out == *"Permission denied"* || $out == *"Operation not permitted"* \
       || $out == *"must be root"* || $out == *"need to be root"* ]]; then echo denied
  else echo nonzero
  fi
}

ev()      { printf '%s\n' "$*" >>"$EVID"; }
ev_head() { { echo; echo "### $1"; [[ -n ${2:-} ]] && echo "\$ $2"; } >>"$EVID"; }
ev_text() { local label=$1; shift; ev_head "$label"; printf '%s\n' "$*" >>"$EVID"; }

term_cmd() { printf '%s\n' "${C_DIM}\$ $*${C_RESET}"; }

# Record result of an evidence command: output + (if not ok) exit/class line.
ev_result() {  # rc out
  local rc=$1 out=$2
  LAST_RC=$rc
  LAST_CLASS=$(classify_result "$rc" "$out")
  if [[ -n $out ]]; then printf '%s\n' "$out" >>"$EVID"
  elif [[ $LAST_CLASS == ok ]]; then echo "(no output)" >>"$EVID"
  fi
  [[ $LAST_CLASS == ok ]] || echo "[exit=${rc} class=${LAST_CLASS}]" >>"$EVID"
}

# run LABEL CMD [ARGS...] : execute a command or a function of this script.
run() {
  local label=$1; shift
  ev_head "$label" "$*"
  term_cmd "$*"
  if ! have "$1"; then
    LAST_RC=127; LAST_CLASS=not_found
    echo "[not_found] '$1' is not installed or not in PATH" >>"$EVID"
    return 127
  fi
  local out rc
  out=$("$@" 2>&1 </dev/null); rc=$?
  ev_result "$rc" "$out"
  return "$rc"
}

# runsh LABEL 'shell string' : for pipelines. Runs in a NEW bash, so it cannot
# call functions defined in this script (use `run` for those).
runsh() {
  local label=$1 cmd=$2 out rc
  ev_head "$label" "$cmd"
  term_cmd "$cmd"
  out=$(bash -c "$cmd" 2>&1 </dev/null); rc=$?
  ev_result "$rc" "$out"
  return "$rc"
}

# runsh_if TOOL LABEL 'shell string' : skip visibly when TOOL is missing.
runsh_if() {
  local tool=$1; shift
  if ! have "$tool"; then
    ev_head "$1"
    echo "[skipped] '$tool' is not installed or not in PATH" >>"$EVID"
    LAST_RC=127; LAST_CLASS=not_found
    return 127
  fi
  runsh "$@"
}

# cap CMD [ARGS...] : quiet capture for findings (no evidence output).
cap() {
  if ! have "$1"; then
    CAP_OUT="'$1' not found"; CAP_RC=127; CAP_CLASS=not_found
    return 127
  fi
  CAP_OUT=$("$@" 2>&1 </dev/null); CAP_RC=$?
  CAP_CLASS=$(classify_result "$CAP_RC" "$CAP_OUT")
  return "$CAP_RC"
}

# ------------------------------------------------------------------
# Findings.  severity (CRIT|WARN|OK|INFO) = what the evidence supports.
#            status   (ok|skipped|error)   = whether the check itself ran.
# Invariant: a check that did not run cleanly can never claim CRIT or OK.
# ------------------------------------------------------------------
finding() {  # id category severity status message...
  local id=$1 cat=$2 sev=$3 st=$4
  shift 4
  case $st in ok|skipped|error) ;; *) st=error ;; esac
  case $sev in CRIT|WARN|OK|INFO) ;; *) sev=INFO; st=error ;; esac
  if [[ $st != ok ]]; then
    case $sev in CRIT) sev=WARN ;; OK) sev=INFO ;; esac
  fi
  F_ID+=("$id"); F_CAT+=("$cat"); F_SEV+=("$sev"); F_ST+=("$st"); F_MSG+=("$*")
}

section() {
  SECTION_NO=$((SECTION_NO+1))
  local title="$SECTION_NO. $1"
  {
    echo
    echo "=================================================================="
    echo "## $title"
    echo "=================================================================="
  } >>"$EVID"
  echo
  echo "${C_BLUE}==================================================================${C_RESET}"
  echo "${C_BOLD}${C_BLUE}## $title${C_RESET}"
  echo "${C_BLUE}==================================================================${C_RESET}"
}

# ------------------------------------------------------------------
# Distro detection
# ------------------------------------------------------------------
detect_distro() {
  local like=""
  if [[ -r /etc/os-release ]]; then
    DISTRO_ID=$(. /etc/os-release; echo "${ID:-unknown}")
    like=$(. /etc/os-release; echo "${ID_LIKE:-}")
    DISTRO_PRETTY=$(. /etc/os-release; echo "${PRETTY_NAME:-}")
  elif [[ -r /etc/redhat-release ]]; then
    DISTRO_ID=rhel
  fi
  case " $DISTRO_ID $like " in
    *" debian "*|*" ubuntu "*)                                  DISTRO_FAMILY=debian ;;
    *" rhel "*|*" centos "*|*" fedora "*|*" rocky "*|*" almalinux "*|*" ol "*) DISTRO_FAMILY=rhel ;;
    *" alpine "*)                                               DISTRO_FAMILY=alpine ;;
    *)                                                          DISTRO_FAMILY=unknown ;;
  esac
  case $DISTRO_FAMILY in
    debian) SUPPORT_LEVEL="primary (Debian/Ubuntu)" ;;
    rhel)   SUPPORT_LEVEL="untested (RHEL family: best effort)" ;;
    alpine) SUPPORT_LEVEL="untested (Alpine: best effort)" ;;
    *)      SUPPORT_LEVEL="unsupported (many checks will be skipped)" ;;
  esac
}

# ------------------------------------------------------------------
# 1. System inventory
# ------------------------------------------------------------------
pkg_count() {
  case $DISTRO_FAMILY in
    # shellcheck disable=SC2016
    debian) dpkg-query -W -f='${db:Status-Abbrev}\n' 2>/dev/null | grep -c '^ii' ;;
    rhel)   rpm -qa 2>/dev/null | wc -l ;;
    alpine) apk info 2>/dev/null | wc -l ;;
    *)      echo unknown ;;
  esac
}

audit_system() {
  section "SYSTEM INVENTORY"
  run   "Kernel / architecture"   uname -a
  runsh "OS release"              "cat /etc/os-release"
  run   "Uptime and load"         uptime
  runsh_if timedatectl "Timezone and clock sync" "timedatectl"
  run   "CPU"                     lscpu
  run   "Memory"                  free -h
  run   "Disk usage"              df -hT -x tmpfs -x devtmpfs -x squashfs
  run   "Block devices"           lsblk
  run   "Installed package count" pkg_count
  runsh_if systemd-detect-virt "Virtualisation" "systemd-detect-virt"

  if (( EUID != 0 )); then
    finding SYS-001 system WARN ok \
      "Audit ran without root privileges (--allow-nonroot): checks that need root are incomplete or skipped"
  fi
}

# ------------------------------------------------------------------
# 2. Services and listening ports
# ------------------------------------------------------------------
audit_services() {
  section "RUNNING SERVICES AND LISTENING PORTS"
  runsh_if systemctl "Running services"         "systemctl list-units --type=service --state=running --no-pager"
  runsh_if systemctl "Enabled services at boot" "systemctl list-unit-files --type=service --state=enabled --no-pager"
  runsh_if systemctl "Failed units"             "systemctl --failed --no-pager"
  run   "Listening TCP/UDP sockets"             ss -tulpn
  runsh_if ss "Listeners on wildcard addresses (listeners bound to a specific public IP are NOT matched)" \
    "ss -tulpnH | awk '\$5 ~ /^(0\\.0\\.0\\.0|\\*|\\[::\\]):/ {print}'"
  runsh_if systemctl "Active systemd timers"    "systemctl list-timers --all --no-pager"
  if (( FULL_EVIDENCE )); then
    runsh "Top 10 processes by memory (WITH arguments; may contain secrets)" "ps aux --sort=-%mem | head -11"
  else
    runsh_if ps "Top 10 processes by memory (command names only; arguments redacted)" \
      "ps -eo user:20,pid,pmem,comm --sort=-pmem | head -11"
  fi
}

# ------------------------------------------------------------------
# 3. Users and access
# ------------------------------------------------------------------
cron_redact() {  # stdin: crontab text -> schedule only
  awk '
    /^[[:space:]]*(#|$)/ {next}
    /^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*=/ {print "  [environment assignment redacted]"; next}
    /^[[:space:]]*@/ {print $1, "[command redacted]"; next}
    {print $1, $2, $3, $4, $5, "[command redacted]"}'
}

cron_system_report() {
  local f
  for f in /etc/crontab /etc/cron.d/*; do
    [[ -f $f ]] || continue
    echo "--- $f"
    if (( FULL_EVIDENCE )); then grep -vE '^[[:space:]]*(#|$)' "$f"; else cron_redact <"$f"; fi
  done
}

cron_user_report() {
  local u
  have crontab || { echo "crontab not installed"; return 127; }
  while IFS=: read -r u _; do
    local t; t=$(crontab -l -u "$u" 2>/dev/null) || continue
    echo "--- user $u"
    if (( FULL_EVIDENCE )); then grep -vE '^[[:space:]]*(#|$)' <<<"$t"; else cron_redact <<<"$t"; fi
  done < <(getent passwd 2>/dev/null || cat /etc/passwd)
}

users_findings() {
  local uid0 others empty
  if have getent; then
    uid0=$(getent passwd 2>/dev/null | awk -F: '$3==0 {print $1}' | paste -sd, -)
  elif [[ -r /etc/passwd ]]; then
    uid0=$(awk -F: '$3==0 {print $1}' /etc/passwd | paste -sd, -)
  else
    uid0=""
  fi
  case $uid0 in
    root) finding USR-001 accounts OK ok "Only 'root' has UID 0" ;;
    "")   finding USR-001 accounts INFO error "Could not enumerate UID 0 accounts (passwd database unreadable or empty)" ;;
    *)
      if [[ ",${uid0}," == *",root,"* ]]; then
        others=$(tr ',' '\n' <<<"$uid0" | grep -vx root | paste -sd, -)
        finding USR-001 accounts CRIT ok "Additional UID 0 account(s) besides root: $(sanitize "$others")"
      else
        finding USR-001 accounts WARN ok "UID 0 is held by '$(sanitize "$uid0")', not 'root' (renamed root account?)"
      fi ;;
  esac

  if [[ -r $SHADOW_FILE ]]; then
    empty=$(awk -F: '$2=="" {print $1}' "$SHADOW_FILE" | paste -sd, -)
    if [[ -n $empty ]]; then
      finding USR-002 accounts CRIT ok "Accounts with an empty password field: $(sanitize "$empty")"
    else
      finding USR-002 accounts OK ok "No accounts with an empty password field"
    fi
  else
    finding USR-002 accounts INFO error "${SHADOW_FILE} is not readable (run as root); empty-password check not performed"
  fi
}

audit_users() {
  section "USERS AND ACCESS"
  runsh "Accounts with a login shell (sync/halt/shutdown excluded)" \
    "grep -vE '(nologin|false|/sync|/halt|/shutdown)\$' /etc/passwd"
  runsh_if getent "UID 0 accounts"  "getent passwd | awk -F: '\$3==0 {print \$1}'"
  runsh "Accounts with an empty password field (names only)" "awk -F: '\$2==\"\" {print \$1}' ${SHADOW_FILE}"
  runsh "Locked accounts (names only, first 20)" "awk -F: '\$2 ~ /^[!*]/ {print \$1}' ${SHADOW_FILE} | head -20"
  runsh_if getent "Members of sudo/wheel/admin groups" "getent group sudo wheel admin"
  runsh "Sudoers (non-comment lines)" \
    "grep -vE '^[[:space:]]*(#|\$)' /etc/sudoers; echo '--- drop-ins ---'; ls -la /etc/sudoers.d/; grep -hvE '^[[:space:]]*(#|\$)' /etc/sudoers.d/*"
  runsh_if last "Recent successful logins" "last -n 20 -a"
  if [[ -s /var/log/btmp ]]; then
    runsh_if lastb "Recent FAILED logins (last 20)" "lastb -n 20 -a"
  else
    ev_text "Recent FAILED logins" "/var/log/btmp missing or empty"
  fi
  runsh "authorized_keys files (names only)" \
    "find /root /home /etc/ssh -maxdepth 3 -name authorized_keys -exec ls -la {} +"
  runsh "Backups of passwd/shadow" "ls -la /etc/passwd- /etc/shadow-"
  if (( FULL_EVIDENCE )); then
    run "Cron jobs, system (FULL commands; may contain secrets)" cron_system_report
    run "Cron jobs, per user (FULL commands; may contain secrets)" cron_user_report
  else
    run "Cron jobs, system (schedules only; commands redacted)" cron_system_report
    run "Cron jobs, per user (schedules only; commands redacted)" cron_user_report
  fi
  users_findings
}

# ------------------------------------------------------------------
# 4. SSH
# ------------------------------------------------------------------
ssh_service_state() {
  SSH_INSTALLED=0; SSH_ACTIVE=0; SSH_ACTIVE_UNITS=""; SSH_LISTENING=unknown
  have sshd && SSH_INSTALLED=1
  if have systemctl; then
    local u
    for u in ssh.service sshd.service ssh.socket sshd.socket; do
      if [[ $(systemctl is-active "$u" 2>/dev/null) == active ]]; then
        SSH_ACTIVE_UNITS+="${SSH_ACTIVE_UNITS:+ }$u"
      fi
    done
  fi
  if have ss; then
    if ss -tlnpH 2>/dev/null | grep -q sshd; then SSH_LISTENING=yes; else SSH_LISTENING=no; fi
  fi
  if [[ -n $SSH_ACTIVE_UNITS || $SSH_LISTENING == yes ]]; then SSH_ACTIVE=1; fi
  return 0
}

ssh_findings() {
  if (( SSH_INSTALLED )); then
    finding SSH-000 ssh INFO ok "SSH server installed; active units: ${SSH_ACTIVE_UNITS:-none}; listening: ${SSH_LISTENING}"
  fi
  if ! have sshd; then
    finding SSH-001 ssh INFO skipped "sshd is not installed; SSH configuration checks skipped"
    return
  fi
  cap sshd -T
  if (( CAP_RC != 0 )); then
    ev_text "sshd -T failure" "exit ${CAP_RC} (${CAP_CLASS}): $(head -3 <<<"$CAP_OUT")"
    finding SSH-001 ssh WARN error \
      "Could not read the effective sshd configuration (sshd -T exit ${CAP_RC}, ${CAP_CLASS}); SSH posture is unknown"
    return
  fi
  local t=$CAP_OUT root pw kbd empty
  ev_text "Effective sshd settings (sshd -T; Match blocks are not evaluated)" \
    "$(grep -E '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|maxauthtries|permitemptypasswords|x11forwarding|logingracetime|clientaliveinterval|allowusers|allowgroups|kbdinteractiveauthentication) ' <<<"$t")"
  root=$(awk '$1=="permitrootlogin"{print $2}' <<<"$t")
  pw=$(awk '$1=="passwordauthentication"{print $2}' <<<"$t")
  kbd=$(awk '$1=="kbdinteractiveauthentication"{print $2}' <<<"$t")
  empty=$(awk '$1=="permitemptypasswords"{print $2}' <<<"$t")

  case $root in
    yes)                                finding SSH-002 ssh CRIT ok "SSH permits root login (PermitRootLogin yes)" ;;
    prohibit-password|without-password) finding SSH-002 ssh WARN ok "SSH allows root login with keys only (PermitRootLogin ${root})" ;;
    forced-commands-only)               finding SSH-002 ssh WARN ok "SSH allows root login only for forced commands" ;;
    no)                                 finding SSH-002 ssh OK   ok "SSH root login is disabled" ;;
    *) finding SSH-002 ssh INFO error "Could not parse PermitRootLogin from sshd -T (value: '$(sanitize "$root")')" ;;
  esac
  case $pw in
    yes) finding SSH-003 ssh WARN ok "SSH password authentication is enabled" ;;
    no)  finding SSH-003 ssh OK   ok "SSH password authentication is disabled" ;;
    *)   finding SSH-003 ssh INFO error "Could not parse PasswordAuthentication from sshd -T" ;;
  esac
  case $kbd in
    yes) finding SSH-004 ssh WARN ok "Keyboard-interactive authentication is enabled; with PAM it may permit password-style logins even if PasswordAuthentication is no" ;;
    no)  finding SSH-004 ssh OK   ok "Keyboard-interactive authentication is disabled" ;;
    *)   finding SSH-004 ssh INFO error "Could not parse KbdInteractiveAuthentication from sshd -T" ;;
  esac
  case $empty in
    yes) finding SSH-005 ssh CRIT ok "SSH permits empty passwords" ;;
    no)  finding SSH-005 ssh OK   ok "SSH does not permit empty passwords" ;;
    *)   finding SSH-005 ssh INFO error "Could not parse PermitEmptyPasswords from sshd -T" ;;
  esac
}

audit_ssh() {
  section "SSH CONFIGURATION"
  ssh_service_state
  ev_text "SSH service state" "sshd installed=${SSH_INSTALLED}; active units=${SSH_ACTIVE_UNITS:-none}; sshd listening=${SSH_LISTENING}"
  runsh "sshd drop-in configs" "ls -la /etc/ssh/sshd_config.d/; cat /etc/ssh/sshd_config.d/*"
  runsh_if systemctl "SSH unit status" "systemctl status ssh.socket ssh.service sshd.service --no-pager | head -15"
  ssh_findings
}

# ------------------------------------------------------------------
# 5. Firewall and network
#    Three separate facts, never conflated:
#      management service active  /  filtering rules present  /  effective
#      protection verified. Absence of evidence is never reported as CRIT.
# ------------------------------------------------------------------
fw_collect() {
  FW_DROP=() FW_ACCEPT=() FW_SERVICES=() FW_UNKNOWN=() FW_INACTIVE=()
  local inc pol nrules hooks

  if have ufw; then
    cap ufw status verbose
    if (( CAP_RC != 0 )); then
      FW_UNKNOWN+=("ufw: could not query (${CAP_CLASS}, exit ${CAP_RC})")
    elif grep -q '^Status: active' <<<"$CAP_OUT"; then
      inc=$(sed -n 's/^Default: \([a-z]*\) (incoming).*/\1/p' <<<"$CAP_OUT")
      case $inc in
        deny|reject) FW_DROP+=("ufw active, default ${inc} incoming") ;;
        allow)       FW_ACCEPT+=("ufw active but default policy allows incoming") ;;
        *)           FW_UNKNOWN+=("ufw active; default incoming policy not parseable") ;;
      esac
    elif grep -q '^Status: inactive' <<<"$CAP_OUT"; then
      FW_INACTIVE+=("ufw installed but inactive")
    else
      FW_UNKNOWN+=("ufw: status output not recognised")
    fi
  fi

  if have firewall-cmd; then
    cap firewall-cmd --state
    if grep -qx running <<<"$CAP_OUT"; then
      FW_SERVICES+=("firewalld running (zone policy not evaluated)")
    elif grep -q 'not running' <<<"$CAP_OUT"; then
      FW_INACTIVE+=("firewalld installed but not running")
    else
      FW_UNKNOWN+=("firewalld: state unknown (${CAP_CLASS}, exit ${CAP_RC})")
    fi
  fi

  if have iptables; then
    cap iptables -S
    if (( CAP_RC != 0 )); then
      FW_UNKNOWN+=("iptables: could not query (${CAP_CLASS}, exit ${CAP_RC})")
    else
      pol=$(awk '$1=="-P" && $2=="INPUT" {print $3}' <<<"$CAP_OUT")
      nrules=$(grep -c '^-A ' <<<"$CAP_OUT" || true)
      if [[ $pol == DROP || $pol == REJECT ]]; then
        FW_DROP+=("iptables INPUT policy ${pol}")
      elif grep -Eq '^-A INPUT -j (DROP|REJECT)' <<<"$CAP_OUT"; then
        FW_DROP+=("iptables INPUT chain ends in an unconditional DROP/REJECT")
      elif [[ $pol == ACCEPT ]] && (( nrules > 0 )); then
        FW_ACCEPT+=("iptables INPUT policy ACCEPT with ${nrules} rule(s) present")
      elif [[ $pol == ACCEPT ]]; then
        FW_INACTIVE+=("iptables present with no rules and INPUT policy ACCEPT")
      else
        FW_UNKNOWN+=("iptables: INPUT policy not parseable")
      fi
    fi
  fi

  if have nft; then
    cap nft list ruleset
    if (( CAP_RC != 0 )); then
      FW_UNKNOWN+=("nftables: could not query (${CAP_CLASS}, exit ${CAP_RC})")
    else
      hooks=$(grep -oE 'hook input priority [^;]+; policy (drop|accept)' <<<"$CAP_OUT" || true)
      if grep -q 'policy drop' <<<"$hooks"; then
        FW_DROP+=("nftables input hook with policy drop")
      elif [[ -n $hooks ]]; then
        FW_ACCEPT+=("nftables input hook(s) present with policy accept")
      elif [[ -n $CAP_OUT ]]; then
        FW_INACTIVE+=("nftables ruleset present but no input hook (no inbound filtering by nft)")
      else
        FW_INACTIVE+=("nftables ruleset empty")
      fi
    fi
  fi
}

fw_findings() {
  if (( ${#FW_DROP[@]} )); then
    finding FW-001 firewall OK ok \
      "Inbound default-deny packet filtering detected: $(join_by '; ' "${FW_DROP[@]}"). Rule contents and actual reachability were not verified"
  elif (( ${#FW_ACCEPT[@]} )); then
    finding FW-001 firewall WARN ok \
      "Filtering rules exist but inbound default policy is accept: $(join_by '; ' "${FW_ACCEPT[@]}"). Verify the rules, or enforce default-deny"
  elif (( ${#FW_SERVICES[@]} )); then
    finding FW-001 firewall INFO ok \
      "Firewall management service active: $(join_by '; ' "${FW_SERVICES[@]}"). Inbound default-deny was not verified"
  elif (( ${#FW_UNKNOWN[@]} )); then
    finding FW-001 firewall INFO error \
      "Host firewall state could not be determined: $(join_by '; ' "${FW_UNKNOWN[@]}")"
  elif (( ${#FW_INACTIVE[@]} )); then
    finding FW-001 firewall WARN ok \
      "Firewall tooling present but not enforcing: $(join_by '; ' "${FW_INACTIVE[@]}"). May be expected if a cloud firewall or upstream ACL provides protection"
  else
    finding FW-001 firewall INFO ok \
      "No host firewall tooling detected (ufw/firewalld/iptables/nft). External enforcement (cloud firewall, security groups, upstream ACLs) cannot be assessed from inside the host; review exposed ports in section 2"
  fi
}

audit_firewall() {
  section "FIREWALL AND NETWORK"
  have ufw          && run "UFW status" ufw status verbose
  have firewall-cmd && runsh "firewalld status" "firewall-cmd --state; firewall-cmd --list-all"
  runsh_if iptables "iptables rules (first 80 lines)" "iptables -S | head -80"
  runsh_if nft      "nftables rules (first 80 lines)" "nft list ruleset | head -80"
  run "IP addresses" ip -br addr
  run "Routes"       ip route
  runsh_if sysctl "Sysctl network hardening" \
    "sysctl net.ipv4.ip_forward net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.rp_filter net.ipv4.tcp_syncookies net.ipv4.conf.all.accept_source_route"
  fw_collect
  fw_findings
}

# ------------------------------------------------------------------
# 6. Updates (local metadata only; never refreshes, never upgrades)
# ------------------------------------------------------------------
metadata_age_days() {
  local f m="" now
  case $DISTRO_FAMILY in
    debian)
      for f in /var/lib/apt/periodic/update-success-stamp /var/lib/apt/lists; do
        if [[ -e $f ]]; then m=$(stat -c %Y -- "$f" 2>/dev/null) && break; fi
      done ;;
    *) ;;
  esac
  if [[ $m =~ ^[0-9]+$ ]]; then
    now=$(date +%s)
    echo $(( (now - m) / 86400 ))
  else
    echo unknown
  fi
}

updates_collect() {
  PKG_TOTAL=unknown PKG_SEC=unknown PKG_NOTE="" PKG_STATUS=error PKG_AGE=unknown
  case $DISTRO_FAMILY in
    debian)
      if ! have apt; then PKG_STATUS=skipped; PKG_NOTE="apt not found"; return; fi
      cap apt list --upgradable
      if (( CAP_RC != 0 )); then
        PKG_NOTE="apt list --upgradable failed (exit ${CAP_RC}, ${CAP_CLASS})"
        ev_text "Pending upgrades" "[error] ${PKG_NOTE}"
        return
      fi
      PKG_TOTAL=$(grep -c 'upgradable from' <<<"$CAP_OUT" || true)
      PKG_SEC=$(awk -F'[/ ]' '/upgradable from/ && $2 ~ /-security/ {n++} END{print n+0}' <<<"$CAP_OUT")
      PKG_STATUS=ok
      PKG_AGE=$(metadata_age_days)
      ev_text "Pending upgrades (local metadata; no refresh performed)" "$(grep 'upgradable from' <<<"$CAP_OUT")"
      ;;
    rhel)
      if ! have dnf; then PKG_STATUS=skipped; PKG_NOTE="dnf not found"; return; fi
      cap dnf -C -q check-update
      case $CAP_RC in
        0)   PKG_TOTAL=0 ;;
        100) PKG_TOTAL=$(awk '/^Obsoleting/ {exit} NF==3 && $1 ~ /\./ {n++} END{print n+0}' <<<"$CAP_OUT") ;;
        *)   PKG_NOTE="dnf -C check-update failed (exit ${CAP_RC}); cache may be missing"
             ev_text "Pending upgrades" "[error] ${PKG_NOTE}"
             return ;;
      esac
      PKG_STATUS=ok
      ev_text "Pending upgrades (dnf cache only; no refresh performed)" "$CAP_OUT"
      cap dnf -C -q updateinfo list security
      if (( CAP_RC == 0 )); then PKG_SEC=$(awk 'NF==3 {n++} END{print n+0}' <<<"$CAP_OUT"); fi
      ;;
    alpine)
      if ! have apk; then PKG_STATUS=skipped; PKG_NOTE="apk not found"; return; fi
      cap apk version -l '<'
      if (( CAP_RC != 0 )); then
        PKG_NOTE="apk version failed (exit ${CAP_RC})"
        ev_text "Pending upgrades" "[error] ${PKG_NOTE}"
        return
      fi
      PKG_TOTAL=$(grep -c '<' <<<"$CAP_OUT" || true)
      PKG_STATUS=ok
      PKG_NOTE="Alpine has no security classification of updates"
      ev_text "Pending upgrades (local index)" "$CAP_OUT"
      ;;
    *)
      PKG_STATUS=skipped; PKG_NOTE="unsupported distribution family" ;;
  esac
}

updates_findings() {
  local age_txt stale=0
  if [[ $PKG_AGE == unknown ]]; then
    age_txt="package metadata age unknown"
  else
    age_txt="package metadata refreshed about ${PKG_AGE} day(s) ago"
    (( PKG_AGE > 7 )) && stale=1
  fi

  case $PKG_STATUS in
    ok)
      if (( PKG_TOTAL > 0 )); then
        finding PKG-001 patching INFO ok "${PKG_TOTAL} package update(s) pending (all kinds; ${age_txt}; metadata was not refreshed)"
      elif [[ $PKG_AGE != unknown ]] && (( ! stale )); then
        finding PKG-001 patching OK ok "No pending updates according to local metadata (${age_txt}; metadata was not refreshed)"
      else
        finding PKG-001 patching INFO ok "No pending updates according to local metadata, but it may be stale (${age_txt})"
      fi
      if [[ $PKG_SEC == unknown ]]; then
        finding PKG-002 patching INFO skipped "Pending security updates cannot be classified on this system${PKG_NOTE:+ ($PKG_NOTE)}"
      elif (( PKG_SEC > 0 )); then
        finding PKG-002 patching WARN ok "${PKG_SEC} pending update(s) are offered from a security repository (heuristic based on repository name; does not prove a specific CVE fix)"
      elif (( stale )) || [[ $PKG_AGE == unknown ]]; then
        finding PKG-002 patching INFO ok "No pending updates from security repositories in local metadata, which may be stale (${age_txt})"
      else
        finding PKG-002 patching OK ok "No pending updates from security repositories in local metadata (${age_txt})"
      fi
      (( stale )) && finding PKG-003 patching WARN ok "Local package metadata is older than 7 days; pending-update counts may be out of date"
      ;;
    skipped)
      finding PKG-001 patching INFO skipped "Update check skipped: ${PKG_NOTE}"
      finding PKG-002 patching INFO skipped "Security-update classification skipped: ${PKG_NOTE}"
      ;;
    *)
      finding PKG-001 patching WARN error "Could not determine pending updates (unknown, not zero): ${PKG_NOTE}"
      finding PKG-002 patching INFO error "Pending security updates unknown: the update check failed"
      ;;
  esac
}

audit_updates() {
  section "UPDATES AND PATCHING"
  updates_collect
  if [[ $DISTRO_FAMILY == debian ]]; then
    runsh "Unattended-upgrades installed?" "dpkg -l unattended-upgrades | tail -1"
    runsh_if systemctl "Unattended-upgrades timers" "systemctl is-enabled apt-daily-upgrade.timer; systemctl is-active apt-daily-upgrade.timer"
    runsh "Unattended-upgrades security origins" "grep -A2 -i 'security' /etc/apt/apt.conf.d/50unattended-upgrades | head -10"
    runsh "Running kernel vs installed" "uname -r; dpkg -l 'linux-image-*' | grep '^ii' | awk '{print \$2, \$3}'"
  fi
  runsh "Reboot required?" "ls -la /var/run/reboot-required; cat /var/run/reboot-required.pkgs"
  updates_findings
  if [[ -f /var/run/reboot-required ]]; then
    finding PKG-004 patching WARN ok "A reboot is required to finish applying updates"
  fi
}

# ------------------------------------------------------------------
# 7. Security tools
# ------------------------------------------------------------------
audit_tools() {
  section "SECURITY TOOLS PRESENT"
  local tool
  for tool in fail2ban-client auditd lynis rkhunter chkrootkit aide apparmor_status; do
    if have "$tool"; then
      ev "[installed] $tool"
      printf '%s[installed]%s %s\n' "$C_GREEN" "$C_RESET" "$tool"
    else
      ev "[MISSING]   $tool"
      printf '%s[MISSING]%s   %s\n' "$C_DIM" "$C_RESET" "$tool"
    fi
  done
  runsh_if fail2ban-client "fail2ban status" "systemctl is-active fail2ban; fail2ban-client status"
  runsh_if aa-status "AppArmor status" "aa-status | head -8"

  if have fail2ban-client; then
    if have systemctl && [[ $(systemctl is-active fail2ban 2>/dev/null) == active ]]; then
      finding SEC-001 tools OK ok "fail2ban is installed and active"
    else
      finding SEC-001 tools WARN ok "fail2ban is installed but not reported active"
    fi
  elif (( ${SSH_ACTIVE:-0} )); then
    finding SEC-001 tools INFO ok "fail2ban is not installed while an SSH service is active; consider ban tooling or other brute-force controls"
  fi
}

# ------------------------------------------------------------------
# 8. File system
# ------------------------------------------------------------------
tmp_findings() {
  local tgt="" fstype="" opts="" line o
  if have findmnt && cap findmnt -n -o TARGET,FSTYPE,OPTIONS --target /tmp; then
    read -r tgt fstype opts <<<"$CAP_OUT"
  fi
  if [[ -z $tgt && -r $MOUNTS_FILE ]]; then
    line=$(awk '$2=="/tmp" {l=$2" "$3" "$4} END{print l}' "$MOUNTS_FILE")
    [[ -n $line ]] || line=$(awk '$2=="/" {l=$2" "$3" "$4} END{print l}' "$MOUNTS_FILE")
    read -r tgt fstype opts <<<"$line"
  fi
  if [[ -z $tgt ]]; then
    finding FS-001 filesystem INFO error "Could not determine the effective /tmp mount state (findmnt unavailable or failed, and ${MOUNTS_FILE} unreadable)"
    return
  fi
  if [[ $tgt != /tmp ]]; then
    finding FS-001 filesystem INFO ok "/tmp is not a separate mount (it lives on '${tgt}'), so nosuid/nodev/noexec cannot be set on it independently. Common default; a dedicated tmpfs or partition with hardened options limits abuse of world-writable space at the cost of some compatibility"
    return
  fi
  finding FS-001 filesystem INFO ok "/tmp is a separate mount (${fstype}); effective options: ${opts}"
  local -A why=(
    [nosuid]="setuid binaries placed in /tmp cannot elevate privileges; low operational cost"
    [nodev]="device nodes in /tmp are ignored; low operational cost"
    [noexec]="direct execution from /tmp is blocked, hindering dropper-style attacks; trade-off: some installers, maintainer scripts and JIT tools need exec on /tmp, and interpreters can still run scripts from it"
  )
  local n=2
  for o in nosuid nodev noexec; do
    if [[ ",${opts}," == *",${o},"* ]]; then
      finding "FS-00${n}" filesystem OK ok "/tmp is mounted ${o}"
    else
      finding "FS-00${n}" filesystem WARN ok "/tmp is a separate mount but lacks ${o}: ${why[$o]}"
    fi
    n=$((n+1))
  done
}

fs_scan() {
  WW_COUNT=0 SUID_COUNT=0
  declare -ga WW_LIST=() SUID_LIST=()
  local tmpf rec mode path frc
  tmpf=$(mktemp) || { finding FS-005 filesystem INFO error "Could not create a temporary file for the filesystem scan"; return; }
  CLEAN_FILES+=("$tmpf")
  find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /tmp \
       -o -path /var/lib/docker -o -path /var/lib/containerd -o -path /var/lib/containers \) -prune \
       -o -type f \( -perm -0002 -o -perm -4000 \) -printf '%m %p\0' >"$tmpf" 2>/dev/null
  frc=$?
  while IFS= read -r -d '' rec; do
    mode=${rec%% *}; path=${rec#* }
    [[ $mode =~ ^[0-7]+$ ]] || continue
    path=${path//[[:cntrl:]]/?}
    if (( (8#$mode & 8#4000) != 0 )); then SUID_COUNT=$((SUID_COUNT+1)); SUID_LIST+=("$mode $path"); fi
    if (( (8#$mode & 8#0002) != 0 )); then
      WW_COUNT=$((WW_COUNT+1))
      (( ${#WW_LIST[@]} < 20 )) && WW_LIST+=("$mode $path")
    fi
  done <"$tmpf"
  ev_head "World-writable regular files (first 20 of ${WW_COUNT}; excludes /proc /sys /dev /run /tmp and container storage)" "find / -xdev ... -perm -0002"
  if (( ${#WW_LIST[@]} )); then printf '%s\n' "${WW_LIST[@]}" >>"$EVID"; else echo "(none)" >>"$EVID"; fi
  ev_head "SUID regular files (${SUID_COUNT})" "find / -xdev ... -perm -4000"
  if (( ${#SUID_LIST[@]} )); then printf '%s\n' "${SUID_LIST[@]}" | sort -k2 >>"$EVID"; else echo "(none)" >>"$EVID"; fi
  if (( frc != 0 )); then
    ev "[find exit=${frc}: scan may be incomplete (permission errors or unsupported find options)]"
    finding FS-005 filesystem INFO error "Filesystem permission scan may be incomplete (find exit ${frc}); counts are lower bounds"
  fi
  if (( WW_COUNT > 0 )); then
    finding FS-006 filesystem WARN ok "${WW_COUNT} world-writable regular file(s) found on the root filesystem (many are benign; review the evidence list)"
  elif (( frc == 0 )); then
    finding FS-006 filesystem OK ok "No world-writable regular files found on the root filesystem outside excluded paths"
  fi
}

audit_fs() {
  section "FILE SYSTEM RISKS"
  runsh_if findmnt "Effective mount options (/tmp, /var/tmp, /dev/shm)" \
    "findmnt -no TARGET,FSTYPE,OPTIONS --target /tmp; findmnt -no TARGET,FSTYPE,OPTIONS --target /var/tmp; findmnt -no TARGET,FSTYPE,OPTIONS --target /dev/shm"
  runsh "fstab entries for /, /home, /tmp, /var (configured, not necessarily mounted)" \
    "awk '\$2 ~ /^\\/(home|tmp|var)?\$/ {print \$1, \$2, \$4}' /etc/fstab"
  runsh "umask defaults" "grep -RE '^[[:space:]]*umask' /etc/profile /etc/bash.bashrc /etc/login.defs | head -10"
  runsh "Key file permissions" "stat -c '%a %U:%G %n' /etc/passwd /etc/shadow /etc/ssh/sshd_config"
  tmp_findings
  fs_scan
}

# ------------------------------------------------------------------
# 9. Authentication log evidence (last 24h)
# ------------------------------------------------------------------
logs_collect() {
  LOG_STATUS=error LOG_FAILS=unknown LOG_NOTE="" LOG_TEXT=""
  if ! have journalctl; then
    LOG_STATUS=skipped; LOG_NOTE="journalctl not available (auth.log files are not parsed by this version)"
    return
  fi
  cap journalctl --no-pager -q --since '24 hours ago' _COMM=sshd _COMM=sshd-session
  if (( CAP_RC != 0 )); then
    LOG_NOTE="journalctl failed (exit ${CAP_RC}, ${CAP_CLASS})"
    return
  fi
  LOG_TEXT=$CAP_OUT
  LOG_FAILS=$(grep -cE 'Failed (password|publickey|keyboard-interactive/pam)' <<<"$LOG_TEXT" || true)
  LOG_STATUS=ok
}

logs_findings() {
  case $LOG_STATUS in
    ok)
      if (( LOG_FAILS > 100 )); then
        finding LOG-001 auth WARN ok "${LOG_FAILS} failed SSH authentication attempts in the last 24h (possible brute-force activity)"
      else
        finding LOG-001 auth INFO ok "${LOG_FAILS} failed SSH authentication attempt(s) in the last 24h (journal source; each failed attempt counted once)"
      fi ;;
    skipped) finding LOG-001 auth INFO skipped "Failed-login count skipped: ${LOG_NOTE}" ;;
    *)       finding LOG-001 auth WARN error "Failed SSH login count is unknown, not zero: ${LOG_NOTE}" ;;
  esac
}

audit_logs() {
  section "LOG EVIDENCE (last 24h)"
  logs_collect
  if [[ $LOG_STATUS == ok ]]; then
    ev_text "Failed SSH authentication attempts (count)" "$LOG_FAILS"
    ev_text "Top 10 source addresses of failed attempts (IPv4/IPv6)" \
      "$(grep -E 'Failed (password|publickey|keyboard-interactive/pam)' <<<"$LOG_TEXT" | grep -oE 'from [0-9A-Fa-f:.]+ port' | awk '{print $2}' | sort | uniq -c | sort -rn | head -10)"
    ev_text "Top 10 usernames tried (from 'Invalid user' lines)" \
      "$(grep -oE 'Invalid user [^ ]+' <<<"$LOG_TEXT" | awk '{print $3}' | sort | uniq -c | sort -rn | head -10)"
    ev_text "Successful SSH logins (usernames and addresses: sensitive)" "$(grep 'Accepted' <<<"$LOG_TEXT")"
  else
    ev_text "SSH log evidence" "[${LOG_STATUS}] ${LOG_NOTE}"
  fi
  runsh "Disk usage of /var/log" "du -sh /var/log"
  logs_findings
}

# ------------------------------------------------------------------
# Optional: Lynis (SYSTEM-MODIFYING)
# ------------------------------------------------------------------
lynis_step() {  # label cmd...
  local label=$1; shift
  ev_head "$label" "$*"
  term_cmd "$*"
  cap "$@"
  printf '%s\n' "$CAP_OUT" >>"$EVID"
  ev "[exit=${CAP_RC}]"
  return "$CAP_RC"
}

audit_lynis() {
  section "LYNIS AUDIT (SYSTEM-MODIFYING MODE)"
  echo "${C_YELLOW}WARNING: --with-lynis may install packages and Lynis writes under /var/log.${C_RESET}" >&2
  ev "NOTICE: --with-lynis was requested. Unlike the default audit, this mode may install the lynis"
  ev "package (and refresh package metadata if the install fails without it)."
  local installed_here=0 idx lyn_tmp lrc
  if ! have lynis; then
    case $DISTRO_FAMILY in
      debian)
        if lynis_step "Install lynis (no metadata refresh first)" apt-get install -y -qq lynis; then
          installed_here=1
        elif lynis_step "Refresh package metadata (system-modifying)" apt-get update -qq \
          && lynis_step "Install lynis (retry)" apt-get install -y -qq lynis; then
          installed_here=1
        fi ;;
      rhel)   lynis_step "Install lynis" dnf install -y lynis && installed_here=1 ;;
      alpine) lynis_step "Install lynis" apk add --no-cache lynis && installed_here=1 ;;
      *)      ev "Cannot install lynis: unsupported distribution family" ;;
    esac
  fi
  if ! have lynis; then
    finding LYN-001 lynis WARN error "Lynis was requested but is not installed and could not be installed"
    return
  fi
  (( installed_here )) && finding LYN-002 lynis INFO ok "Lynis package was installed by this run (system was modified)"

  lyn_tmp=$(mktemp "$OUTDIR/.partial-lynis-XXXXXX") || { finding LYN-001 lynis WARN error "Cannot create temp file for Lynis output"; return; }
  CLEAN_FILES+=("$lyn_tmp")
  lynis audit system --quick --no-colors >"$lyn_tmp" 2>&1 </dev/null; lrc=$?
  LYNIS_FINAL="$OUTDIR/lynis-${HOST}-${STAMP}-${RAND}.txt"
  if finalize_file "$lyn_tmp" "$LYNIS_FINAL"; then
    ev "Full Lynis output: $(basename -- "$LYNIS_FINAL") (exit ${lrc})"
  else
    ev "Could not store the full Lynis output safely (exit ${lrc})"; LYNIS_FINAL=""
  fi
  idx=$(sed -n 's/^hardening_index=//p' /var/log/lynis-report.dat 2>/dev/null | tail -1)
  if [[ $idx =~ ^[0-9]+$ ]]; then
    finding LYN-003 lynis INFO ok "Lynis hardening index: ${idx}"
  else
    finding LYN-003 lynis WARN error "Lynis ran (exit ${lrc}) but the hardening index could not be read from /var/log/lynis-report.dat"
  fi
  runsh "Lynis warnings"            "grep '^warning\\[\\]' /var/log/lynis-report.dat"
  runsh "Lynis suggestions (first 30)" "grep '^suggestion\\[\\]' /var/log/lynis-report.dat | head -30"
}

# ------------------------------------------------------------------
# Reports
# ------------------------------------------------------------------
count_by() {  # array-name value -> count (F_SEV / F_ST)
  local -n arr=$1; local x n=0
  for x in "${arr[@]}"; do [[ $x == "$2" ]] && n=$((n+1)); done
  echo "$n"
}

mode_text() { if (( WITH_LYNIS )); then echo "with-lynis (SYSTEM-MODIFYING)"; else echo "default (read-only intent)"; fi; }
priv_text() { if (( EUID == 0 )); then echo root; else echo non-root; fi; }

summary_text() {
  local want i
  echo "==================== BASELINE AUDIT REPORT ===================="
  echo "Tool: baseline_audit.sh v${VERSION} (JSON schema ${SCHEMA_VERSION})"
  echo "Host: ${HOST}   Date (UTC): ${STAMP}"
  echo "Distro: ${DISTRO_PRETTY:-$DISTRO_ID} (id=${DISTRO_ID}, family=${DISTRO_FAMILY}; support: ${SUPPORT_LEVEL})"
  echo "Mode: $(mode_text)   Privileges: $(priv_text)   Evidence detail: $( ((FULL_EVIDENCE)) && echo full || echo standard)"
  echo "SENSITIVE: contains usernames, IPs, services, paths and login history. Do not publish unredacted."
  echo "==================== SUMMARY ===================="
  echo "Severity (what the evidence supports): CRIT $(count_by F_SEV CRIT)  WARN $(count_by F_SEV WARN)  INFO $(count_by F_SEV INFO)  OK $(count_by F_SEV OK)"
  echo "Check status (did the check run?):     ok $(count_by F_ST ok)  skipped $(count_by F_ST skipped)  error $(count_by F_ST error)"
  echo "Rows with status skipped/error mean the evidence is incomplete: treat them as UNKNOWN, not as pass or fail."
  echo "-------------------------------------------------"
  for want in CRIT WARN INFO OK; do
    for i in "${!F_ID[@]}"; do
      [[ ${F_SEV[i]} == "$want" ]] || continue
      printf '%-5s %-8s %-8s %s\n' "$want" "${F_ST[i]}" "${F_ID[i]}" "$(sanitize "${F_MSG[i]}")"
    done
  done
  echo "=================================================="
  echo
  echo "===================== EVIDENCE ====================="
}

print_terminal_summary() {
  local want i col label
  echo
  echo "${C_BOLD}==================== SUMMARY ====================${C_RESET}"
  printf '  CRIT %s   WARN %s   INFO %s   OK %s   |   status: ok %s, skipped %s, error %s\n' \
    "$(count_by F_SEV CRIT)" "$(count_by F_SEV WARN)" "$(count_by F_SEV INFO)" "$(count_by F_SEV OK)" \
    "$(count_by F_ST ok)" "$(count_by F_ST skipped)" "$(count_by F_ST error)"
  for want in CRIT WARN INFO OK; do
    case $want in CRIT) col=$C_RED;; WARN) col=$C_YELLOW;; OK) col=$C_GREEN;; *) col=$C_DIM;; esac
    for i in "${!F_ID[@]}"; do
      [[ ${F_SEV[i]} == "$want" ]] || continue
      label="[$want]"; [[ ${F_ST[i]} == ok ]] || label="[$want/${F_ST[i]}]"
      printf '%s%-16s%s %s\n' "$col" "$label" "$C_RESET" "$(sanitize "${F_MSG[i]}")"
    done
  done
  echo "${C_BOLD}=================================================${C_RESET}"
}

read -r -d '' PY_JSON <<'PY'
import json, sys
a = sys.argv[1:]
if len(a) % 2:
    sys.exit("meta arguments must be key/value pairs")
meta = dict(zip(a[0::2], a[1::2]))
parts = sys.stdin.buffer.read().split(b"\0")
if parts and parts[-1] == b"":
    parts.pop()
if len(parts) % 5:
    sys.exit("malformed finding stream")
dec = lambda b: b.decode("utf-8", "replace")
keys = ("id", "category", "severity", "status", "message")
findings = [dict(zip(keys, map(dec, parts[i:i + 5]))) for i in range(0, len(parts), 5)]
summary = {"severity": {}, "status": {}}
for f in findings:
    for k in ("severity", "status"):
        summary[k][f[k]] = summary[k].get(f[k], 0) + 1
doc = {"schema_version": 2, "meta": meta, "summary": summary, "findings": findings}
json.dump(doc, sys.stdout, indent=2, ensure_ascii=True)
sys.stdout.write("\n")
PY

# write_json DEST : serialise findings with Python's json module.
write_json() {
  local dest=$1 i
  if ! have python3; then
    echo "python3 not found: JSON report cannot be produced" >&2
    return 2
  fi
  {
    for i in "${!F_ID[@]}"; do
      printf '%s\0%s\0%s\0%s\0%s\0' "${F_ID[i]}" "${F_CAT[i]}" "${F_SEV[i]}" "${F_ST[i]}" "${F_MSG[i]}"
    done
  } | python3 -c "$PY_JSON" \
        tool baseline_audit.sh \
        version "$VERSION" \
        host "$HOST" \
        date_utc "$STAMP" \
        distro_id "$DISTRO_ID" \
        distro_family "$DISTRO_FAMILY" \
        distro_pretty "$DISTRO_PRETTY" \
        support_level "$SUPPORT_LEVEL" \
        mode "$(mode_text)" \
        privileges "$(priv_text)" \
        evidence_detail "$( ((FULL_EVIDENCE)) && echo full || echo standard)" \
        text_report "$(basename -- "${FINAL_TXT:-none}")" \
        >"$dest"
}

validate_json() {
  python3 -c 'import json,sys; json.load(open(sys.argv[1], encoding="utf-8"))' "$1" 2>/dev/null
}

write_text_report() {
  local tmp
  tmp=$(mktemp "$OUTDIR/.partial-report-XXXXXX") || return 1
  CLEAN_FILES+=("$tmp")
  { summary_text; cat -- "$EVID"; } >"$tmp" || return 1
  finalize_file "$tmp" "$FINAL_TXT"
}

write_json_report() {
  local tmp
  tmp=$(mktemp "$OUTDIR/.partial-json-XXXXXX") || return 1
  CLEAN_FILES+=("$tmp")
  write_json "$tmp" || return 1
  validate_json "$tmp" || { echo "generated JSON failed validation; not publishing it" >&2; return 1; }
  finalize_file "$tmp" "$FINAL_JSON"
}

# ------------------------------------------------------------------
# main
# ------------------------------------------------------------------
main() {
  export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
  if [[ -n ${BA_EXTRA_PATH:-} ]]; then      # test hook: directory of mock binaries
    PATH="${BA_EXTRA_PATH}:${PATH}"
    echo "TEST MODE: BA_EXTRA_PATH is set; command lookups may be mocked" >&2
  fi

  parse_args "$@"
  if (( EUID != 0 )) && (( ! ALLOW_NONROOT )); then
    die "run with sudo so all checks can read logs and config (or use --allow-nonroot for a partial audit)" 1
  fi
  umask 077

  HOST=$(hostname 2>/dev/null); HOST=${HOST//[^A-Za-z0-9._-]/_}; [[ -n $HOST ]] || HOST=unknown
  STAMP=$(date -u +%Y%m%dT%H%M%SZ)
  RAND=$(od -An -N4 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n'); [[ -n $RAND ]] || RAND=$$
  detect_distro
  prepare_output

  trap cleanup EXIT
  trap '(( FINALIZED )) || echo "Interrupted: no report was written." >&2; exit 130' INT
  trap '(( FINALIZED )) || echo "Terminated: no report was written." >&2; exit 143' TERM

  echo "Auditing (mode: $(mode_text))..."
  echo "Distro: ${DISTRO_ID} (family: ${DISTRO_FAMILY}; support: ${SUPPORT_LEVEL})"
  if (( WITH_LYNIS )); then
    echo "${C_YELLOW}--with-lynis: this run may modify the system (package install, /var/log).${C_RESET}"
  fi

  audit_system
  audit_services
  audit_users
  audit_ssh
  audit_firewall
  audit_updates
  audit_tools
  audit_fs
  audit_logs
  (( WITH_LYNIS )) && audit_lynis

  local rc=0
  print_terminal_summary
  if ! write_text_report; then
    echo "ERROR: could not write the text report safely" >&2; rc=5
  fi
  if ! write_json_report; then
    echo "ERROR: could not write the JSON report" >&2; (( rc == 0 )) && rc=4
  fi
  FINALIZED=1
  echo
  [[ -f $FINAL_TXT  ]] && echo "Text report : $FINAL_TXT"
  [[ -f $FINAL_JSON ]] && echo "JSON report : $FINAL_JSON"
  [[ -n $LYNIS_FINAL && -f $LYNIS_FINAL ]] && echo "Lynis output: $LYNIS_FINAL"
  echo "Reports are root-readable only (mode 0600) and contain sensitive data. Review before sharing."
  exit "$rc"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
