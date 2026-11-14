#!/usr/bin/env bash
#
# harden-debian12.sh — generic Debian 12 (bookworm) security hardening
#
# What it does (all steps idempotent, safe to re-run):
#   1. Points APT at the current stable bookworm repos (only if frozen/stale),
#      runs apt update + upgrade, and ensures EXTRA_PACKAGES are at latest stable.
#   2. Installs and enables UFW with the SSH port allowed first (protects SSH).
#   3. Hardens PAM: PASS_MIN_DAYS 7, password minlen 12 (pam_pwquality),
#      and removes 'nullok'.
#   4. Hardens sysctl: net.ipv4.tcp_syncookies=1, net.ipv4.ip_forward=0 (+ applies).
#   5. /etc/shadow permissions -> 640.
#   6. APT::Periodic::Update-Package-Lists (set LAST, so APT cannot revert it).
#   7. Disables UNWANTED_SERVICES (skipped if not installed; sshd is NEVER touched).
#   8. Optional: removes a rogue 'nc.traditional' shell backdoor (binary, processes,
#      and its root crontab line) if present.
#
# Intentionally OUT OF SCOPE (machine/scenario-specific judgments):
#   - user account management (creating, deleting, passwords, group membership)
#   - forensics questions / evidence files
#   - enabling or disabling business-critical services
#   - deleting personal media or content files
#
# Usage: sudo bash harden-debian12.sh [--skip-apt] [--no-backdoor-cleanup]
#
set -u

# ============================ CONFIG ==========================================
SSH_PORT=22                                   # port to allow through UFW
UNWANTED_SERVICES=(apache2 vsftpd)            # non-essential services to disable
EXTRA_PACKAGES=(chromium openssh-server)      # ensure these are at latest stable
PERIODIC_UPDATE_LISTS="1"                     # APT::Periodic::Update-Package-Lists
PASS_MIN_DAYS=7
PW_MINLEN=12
RUN_BACKDOOR_CLEANUP=1
SKIP_APT=0
# ==============================================================================

for a in "$@"; do
  case "$a" in
    --skip-apt) SKIP_APT=1 ;;
    --no-backdoor-cleanup) RUN_BACKDOOR_CLEANUP=0 ;;
  esac
done

log()  { echo -e "[$(date '+%H:%M:%S')] $*"; }
fail() { echo -e "  ! $*" >&2; }

[ "$(id -u)" = "0" ] || { echo "Run as root: sudo bash $0" >&2; exit 2; }
. /etc/os-release 2>/dev/null || true
log "Host: $HOSTNAME | ${PRETTY_NAME:-unknown distro}"
[ "${ID:-}" = "debian" ] || log "WARNING: this machine is not Debian; continuing anyway."

# ---------------------------------------------------------------- 1. APT ------
if [ "$SKIP_APT" = "1" ]; then
  log "APT phase skipped (--skip-apt)"
else
  # If sources.list is a frozen snapshot or missing bookworm, restore live repos.
  if [ -f /etc/apt/sources.list ] && grep -qE 'snapshot\.debian\.org|archive\.debian\.org' /etc/apt/sources.list; then
    log "sources.list points at an archived/snapshot repo -> restoring live bookworm repos"
    cp -a /etc/apt/sources.list /etc/apt/sources.list.bak.$(date +%Y%m%d)
    cat > /etc/apt/sources.list <<'EOF'
deb http://deb.debian.org/debian bookworm main contrib non-free non-free-firmware
deb http://deb.debian.org/debian bookworm-updates main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security bookworm-security main contrib non-free non-free-firmware
EOF
  elif [ ! -f /etc/apt/sources.list ] || ! grep -q 'bookworm' /etc/apt/sources.list; then
    log "WARNING: /etc/apt/sources.list does not mention bookworm; leaving it alone"
  fi

  export DEBIAN_FRONTEND=noninteractive
  log "apt-get update"
  apt-get update || fail "apt-get update failed (continuing)"
  log "apt-get upgrade (this can take a while)"
  apt-get -y upgrade || fail "apt-get upgrade failed (continuing)"
  if [ ${#EXTRA_PACKAGES[@]} -gt 0 ]; then
    log "ensuring latest stable: ${EXTRA_PACKAGES[*]}"
    apt-get install -y "${EXTRA_PACKAGES[@]}" || fail "extra package install failed"
  fi
fi

# ---------------------------------------------------------------- 2. UFW ------
log "UFW"
if ! dpkg -s ufw >/dev/null 2>&1; then
  apt-get install -y ufw || fail "could not install ufw"
fi
ufw allow "$SSH_PORT/tcp" >/dev/null 2>&1 || fail "ufw allow failed"
ufw --force enable >/dev/null 2>&1 || fail "ufw enable failed"
ufw status 2>/dev/null | sed 's/^/  /'

# ---------------------------------------------------------------- 3. PAM ------
log "PAM hardening"
cp -a /etc/pam.d /root/pam.d.bak.$(date +%Y%m%d) 2>/dev/null || true

# 3a. PASS_MIN_DAYS
sed -ri "s/^(#\s*)?PASS_MIN_DAYS\s+.*$/PASS_MIN_DAYS\t${PASS_MIN_DAYS}/" /etc/login.defs
grep -qE "^PASS_MIN_DAYS\s+${PASS_MIN_DAYS}\s*$" /etc/login.defs \
  && log "PASS_MIN_DAYS = $(grep -cE "^PASS_MIN_DAYS\s+${PASS_MIN_DAYS}\s*$" /etc/login.defs) ok" \
  || fail "PASS_MIN_DAYS not set"

# 3b. common-auth: remove nullok
if grep -q 'nullok' /etc/pam.d/common-auth; then
  sed -i 's/pam_unix\.so nullok/pam_unix.so/' /etc/pam.d/common-auth
  log "removed 'nullok' from common-auth"
fi
grep -q 'pam_unix.so' /etc/pam.d/common-auth || fail "common-auth missing pam_unix.so — inspect it"

# 3c. common-password: minlen via pam_pwquality
if ! dpkg -s libpam-pwquality >/dev/null 2>&1; then
  apt-get install -y libpam-pwquality || fail "could not install libpam-pwquality"
fi
if ! grep -q "minlen=${PW_MINLEN}" /etc/pam.d/common-password; then
  if grep -q 'pam_pwquality.so' /etc/pam.d/common-password; then
    sed -ri "s/(pam_pwquality\.so[^ ]*)/\1 local_users_only minlen=${PW_MINLEN}/" /etc/pam.d/common-password
  elif grep -q 'pam_unix.so' /etc/pam.d/common-password; then
    sed -i "/pam_unix.so/a password	requisite			pam_pwquality.so local_users_only minlen=${PW_MINLEN}" /etc/pam.d/common-password
  else
    fail "common-password has no pam_unix.so line; added nothing — inspect manually"
  fi
  log "minlen=${PW_MINLEN} enforced via pam_pwquality"
else
  log "minlen=${PW_MINLEN} already present"
fi
grep -q "minlen=${PW_MINLEN}" /etc/pam.d/common-password \
  && log "common-password ok" || fail "minlen not present in common-password"

# ---------------------------------------------------------------- 4. sysctl ---
log "sysctl"
for kv in "net.ipv4.tcp_syncookies=1" "net.ipv4.ip_forward=0"; do
  k=${kv%%=*}; v=${kv#*=}
  if grep -qE "^\s*#?\s*${k}\s*=" /etc/sysctl.conf; then
    sed -ri "s/^\s*#?\s*${k}\s*=.*/${k}=${v}/" /etc/sysctl.conf
  else
    echo "${k}=${v}" >> /etc/sysctl.conf
  fi
done
sysctl -p >/dev/null 2>&1
log "live values: $(sysctl net.ipv4.tcp_syncookies net.ipv4.ip_forward 2>/dev/null | tr '\n' ' ')"

# -------------------------------------------------------------- 5. shadow -----
log "/etc/shadow permissions"
chmod 640 /etc/shadow
stat -c '%a' /etc/shadow | grep -q '^640$' && log "shadow perms 640 ok" || fail "shadow perms wrong"

# ---------------------------------------------------------- 6. services -------
log "services"
for s in "${UNWANTED_SERVICES[@]}"; do
  case "$s" in *ssh*) log "skipping critical service: $s"; continue ;; esac
  if dpkg -s "$s" >/dev/null 2>&1; then
    systemctl disable --now "$s" 2>/dev/null && log "disabled $s" || fail "could not disable $s"
  else
    log "$s not installed — nothing to do"
  fi
done
log "sshd: $(systemctl is-enabled ssh 2>/dev/null || systemctl is-enabled sshd 2>/dev/null) / $(systemctl is-active ssh 2>/dev/null || systemctl is-active sshd 2>/dev/null)"

# ---------------------------------------------------- 7. backdoor cleanup -----
if [ "$RUN_BACKDOOR_CLEANUP" = "1" ]; then
  log "rogue netcat backdoor check"
  if [ -e /usr/bin/nc.traditional ]; then
    pkill -f 'nc[.]traditional' 2>/dev/null && log "killed rogue nc.traditional processes"
    rm -f /usr/bin/nc.traditional
    log "removed /usr/bin/nc.traditional"
  else
    log "no nc.traditional binary present"
  fi
  if crontab -l 2>/dev/null | grep -q 'nc\.traditional'; then
    crontab -l 2>/dev/null | grep -v 'nc\.traditional' | crontab -
    log "stripped nc.traditional line from root crontab"
  else
    log "root crontab clean"
  fi
fi

# ------------------------------------------------- 8. APT periodic (LAST) -----
log "APT periodic (applied last so APT cannot revert it)"
echo "APT::Periodic::Update-Package-Lists \"${PERIODIC_UPDATE_LISTS}\";" > /etc/apt/apt.conf.d/20auto-upgrades
cat /etc/apt/apt.conf.d/20auto-upgrades | sed 's/^/  /'

# ---------------------------------------------------------------- summary -----
echo
log "=== SUMMARY ==="
echo "  PASS_MIN_DAYS   : $(grep -E '^PASS_MIN_DAYS' /etc/login.defs | awk '{print $2}')"
echo "  nullok          : $(grep -q 'nullok' /etc/pam.d/common-auth && echo PRESENT || echo removed)"
echo "  minlen          : $(grep -oE 'minlen=[0-9]+' /etc/pam.d/common-password || echo MISSING)"
echo "  tcp_syncookies  : $(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)"
echo "  ip_forward      : $(sysctl -n net.ipv4.ip_forward 2>/dev/null)"
echo "  shadow perms    : $(stat -c '%a' /etc/shadow)"
echo "  ufw             : $(ufw status 2>/dev/null | head -1)"
echo "  nc backdoor     : $( [ -e /usr/bin/nc.traditional ] && echo PRESENT || echo absent )"
echo "  apt periodic    : $(cat /etc/apt/apt.conf.d/20auto-upgrades)"
echo
log "Done. Re-run anytime — every step is idempotent."
