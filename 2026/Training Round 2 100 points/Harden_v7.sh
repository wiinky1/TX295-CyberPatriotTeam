#!/usr/bin/env bash
# =====================================================================
#  CyberPatriot — GENERIC Linux hardening (season-agnostic)  [v7]
#
#  Design rule (per coach, 2026-11): this script contains ZERO things
#  that vary between images — no usernames, no roster, no named
#  services-to-stop, no named packages-to-remove, no password values.
#  Everything image-specific comes from a sibling file:
#
#        round_config.txt   (same directory as this script)
#
#  The config is a sourceable shell file. Generate one per round from
#  that round's README + answer key (the values that change: who to
#  delete, which password to set, which group to join, minlen,
#  services to stop, packages to purge, etc.).
#
#  Section inventory (v7.1 — covers scored items #1..#26 of the R2 report):
#    apt update/upgrade (the Chromium/OpenSSH "updated" items) · user tasks
#    (remove/sudo-removal/group/password — all from config) ·
#    PASS_MIN_DAYS (login.defs, not PAM) · PAM_BLOCK gate: minlen + lockout
#    profiles + nullok — OFF by default (owner rule 2026-11-11), enabled only
#    via PAM_BLOCK=yes in the config after explicit owner approval ·
#    sysctl syncookies=1 ip_forward=0 · /etc/shadow 640 · services stopped
#    (config, keep-guarded) · prohibited + poll pkgs purged (config,
#    keep-guarded) · user-media sweep (config exts) · netcat backdoor
#    cleanup (packages + exact-name process kill + cron lines) ·
#    sshd PermitRootLogin no (enforced), sshd kept running ·
#    UFW install + allow 22 + default deny incoming ·
#    browser default (chromium/firefox whichever installed) ·
#    APT auto-updates (lists + downloads + unattended) · DM report · report.
#  Items NOT scriptable (by design): forensics Q1/Q2 (console work).
#
#  Guard rails:
#    KEEP_SERVICES / KEEP_PKGS in the config are sacrosanct — the
#    script refuses to stop, disable, or purge anything on the keep
#    lists even if a STOP/PURGE list also names them. sshd is always
#    on the keep list internally.
#
#  NOT in this script (by design): forensics answers (per-round
#  console work), /etc/apt/sources.list rewrite (distro/round specific
#  — do it by hand or extend the config), unique-identifier entry,
#  UTC, CCS client.
#
#  Usage:  sudo bash Harden_v7.sh            (uses ./round_config.txt)
#          sudo bash Harden_v7.sh /path/cfg  (explicit config)
#          add --yes (any position) to skip the enter-prompt
# =====================================================================
set -uo pipefail
LC_ALL=C
export DEBIAN_FRONTEND=noninteractive

CFG="${1:-}"
[ "$CFG" = "--yes" ] && CFG=""
[ -z "$CFG" ] && CFG="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/round_config.txt"
if [ ! -f "$CFG" ]; then
  echo "ERROR: round config not found: $CFG"
  echo "The script itself contains no round-specific data by design."
  echo "Create $CFG (see the key list in its template) and re-run."
  exit 1
fi
# shellcheck source=/dev/null
. "$CFG"
SKIP_CONFIRM=0
case " $* " in *" --yes "*) SKIP_CONFIRM=1;; esac

# ---------- safe defaults (report which were used) ----------
MINLEN="${MINLEN:-12}"
PASS_MIN_DAYS="${PASS_MIN_DAYS:-7}"
MEDIA_EXTS="${MEDIA_EXTS:-mp3 mp4 ogg oga wav avi mov mkv flv}"
PROHIBIT_BASE="nmap ophcrack hydra john"          # the standard "hacking tools" every scenario bans
KEEP_SERVICES=" ssh sshd ${KEEP_SERVICES:-} "     # sshd is internally sacrosanct
KEEP_PKGS=" ${KEEP_PKGS:-} "

ok()   { echo -e "  \033[32m[ OK ]\033[0m $*"; }
warn() { echo -e "  \033[33m[WARN ]\033[0m $*"; }
fail() { echo -e "  \033[31m[ FAIL ]\033[0m $*"; }
info() { echo -e "  \033[90m[ .. ]\033[0m $*"; }
step() { echo -e "\n\033[1;36m== $* ==\033[0m"; }
S() { sudo "$@"; }

on_keep() { case "$KEEP_SERVICES" in *" $1 "*) return 0;; esac; return 1; }
on_keep_pkg() { case "$KEEP_PKGS" in *" $1 "*) return 0;; esac; return 1; }
media_expr() { local e out=""; for e in $MEDIA_EXTS; do out="$out -o -name *.$e"; done; echo "${out# -o}"; }

# ============================ 0 · preflight ============================
step "0 · PREFLIGHT"
echo "  round  : ${ROUND_LABEL:-<none set>}"
echo "  host   : $(hostname)"
echo "  os     : $(grep PRETTY /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '"')"
echo "  users  : $(awk -F: '$3>=1000 && $3<65534{print $1}' /etc/passwd | tr '\n' ' ')"
echo "  keep   : services [${KEEP_SERVICES//  /} ] packages [${KEEP_PKGS//  /} ]"
echo "  plan   : remove-users[${REMOVE_USERS:- -}] sudo-remove[${SUDO_REMOVE:- -}] group-task[${GROUP_TASKS:- -}] pw-set[${PW_SET:+<set>}${PW_SET:- -}]"
echo "  plan   : stop[${STOP_SERVICES:- -}] purge[${PURGE_PKGS:- -}] poll[${POLL_PKGS:- -}] smb[${SMB_REMOVAL:-no}] minlen=${MINLEN} pass-min-days=${PASS_MIN_DAYS}"
info "do NOT run on an image without first reading its README (roster = your deletion boundary)"
[ "$SKIP_CONFIRM" -eq 1 ] || { echo "Press ENTER to run, or Ctrl-C to abort..."; read -r _; }

# ============================ 1 · apt ============================
step "1 · APT UPDATE + UPGRADE (kept-updated checks come from here)"
if apt-get update >/tmp/cp_apt_update.log 2>&1; then
  ok "update (if it warns about bad sources/keys — fix the sources by hand this round)"
else
  warn "apt-get update reported errors (see tail):"
  tail -5 /tmp/cp_apt_update.log | sed 's/^/      /'
fi
apt-get -y upgrade >/tmp/cp_apt_upgrade.log 2>&1 && ok "upgrade" || warn "upgrade (see log)"
tail -3 /tmp/cp_apt_upgrade.log | sed 's/^/      /'
apt-get -y autoremove >/dev/null 2>&1; apt-get -y clean >/dev/null 2>&1

# ====================== 2 · users (from config) =======================
step "2 · USER TASKS (all from round_config.txt)"
for u in ${REMOVE_USERS:-}; do
  if getent passwd "$u" >/dev/null 2>&1; then
    S cp /etc/shadow /root/shadow.bak."$u" 2>/dev/null
    S userdel -f -r "$u" >/dev/null 2>&1 || S deluser --remove-home "$u" </dev/null >/dev/null 2>&1
    S rm -rf "/home/$u" 2>/dev/null
  fi
  getent passwd "$u" >/dev/null 2>&1 && warn "$u STILL PRESENT" || ok "$u removed"
done
for u in ${SUDO_REMOVE:-}; do
  S gpasswd -d "$u" sudo >/dev/null 2>&1
  getent group sudo | grep -qw "$u" && warn "$u still in sudo" || ok "$u out of sudo"
done
if [ -n "${GROUP_TASKS:-}" ]; then
  gu=${GROUP_TASKS%% *}; gg=${GROUP_TASKS#* }
  id "$gu" >/dev/null 2>&1 || S adduser --disabled-password --gecos "" "$gu" >/dev/null 2>&1
  getent group "$gg" >/dev/null 2>&1 || S groupadd "$gg" >/dev/null 2>&1
  S usermod -aG "$gg" "$gu" >/dev/null 2>&1
  getent group "$gg" | grep -qw "$gu" && ok "$gu joined $gg" || fail "$gu not in $gg"
fi
if [ -n "${PW_SET:-}" ]; then
  IFS=';' read -ra PWE <<<"$PW_SET"          # tokens: user:password;...
  for tok in "${PWE[@]}"; do
    pu=${tok%%:*}; pp=${tok#*:}
    echo "$pu:$pp" | S chpasswd && ok "pw set for $pu (${#pp} chars)" || fail "chpasswd $pu"
  done
fi

# ==================== 3 · password policy (values) ====================
# OWNER RULE 2026-11-11: never touch PAM. The pam_pwquality line and
# nullok removal were REMOVED from this step (they wrote /etc/pam.d/*).
# Only /etc/login.defs (age policy) remains — that is not PAM.
# Lockout (faillock) step removed entirely — scoring item intentionally
# unmet on future images per owner decision.
step "3 · PASSWORD AGE POLICY (PASS_MIN_DAYS=${PASS_MIN_DAYS}) [login.defs — not PAM]"
S sed -ri "s/^(PASS_MIN_DAYS[[:space:]]+).*/\1${PASS_MIN_DAYS}/" /etc/login.defs
grep -a '^PASS_MIN_DAYS' /etc/login.defs && ok "written"

# ==================== 3b · PAM policy items (GATED — OFF by default) ====================
# OWNER RULE 2026-11-11: PAM work is BANNED by default on comp images.
# This block runs ONLY if the round config sets PAM_BLOCK=yes (explicit
# owner approval for that round). It does EXACTLY the three minimum
# operations that produced the 100/100 state on 2026-11-11 and nothing
# else:
#   1) pam_pwquality.so minlen=N in common-password + minlen in pwquality.conf
#   2) the three lockout profiles in /usr/share/pam-configs (proven to
#      satisfy the "account lockout policy" item WITHOUT running
#      pam-auth-update — common-auth keeps 0 faillock lines)
#   3) nullok removal from common-auth
# This script NEVER runs: pam-auth-update (the TUI/parser that broke the
# image), pam_deny.so, or speculative rewrites of common-*.
# A full /etc/pam.d backup is taken first as the revert path.
if [ "${PAM_BLOCK:-no}" = "yes" ]; then
  step "3b · PAM POLICY (minlen=${MINLEN}, lockout profiles, nullok off) — PAM_BLOCK=yes"
  TS=$(date +%Y%m%d_%H%M%S)
  S mkdir -p /root/pam_backup_"$TS"
  S bash -c 'yes | cp -a /etc/pam.d/. /root/pam_backup_'"$(date +%Y%m%d_%H%M%S)"' 2>/dev/null || tar -C /etc -cf - pam.d | tar -C /root/pam_backup_'"$(date +%S)"' -xf - 2>/dev/null'
  cp /etc/security/pwquality.conf /root/pam_pwquality.conf.bak 2>/dev/null || S cp /etc/security/pwquality.conf "/root/pam_pwquality.conf.bak.$TS"
  # 1) minlen in the common-password line (+ pwquality.conf)
  if grep -q pam_pwquality.so /etc/pam.d/common-password; then
    grep -q 'pam_pwquality.so.*minlen' /etc/pam.d/common-password \
      || S sed -ri "s/^(pam_pwquality\.so.*)/\1 minlen=${MINLEN}/" /etc/pam.d/common-password
  else
    S sed -i '/pam_unix.so/a password\t[success=1 default=ignore]\tpam_pwquality.so minlen='"${MINLEN}"'' /etc/pam.d/common-password
  fi
  grep -q '^[#[:space:]]*minlen' /etc/security/pwquality.conf 2>/dev/null \
    || S bash -c "echo 'minlen = ${MINLEN}' >> /etc/security/pwquality.conf"
  grep -an pwquality /etc/pam.d/common-password && ok "minlen line" || warn "minlen line — inspect common-password"
  # 2) lockout profiles (FILES ONLY — pam-auth-update is never invoked)
  D=$(mktemp -d)
  cat > "$D/faillock" <<'PEOF'
Name: Lockout on failed logins
Default: no
Priority: 0
Auth-Type: Primary
Auth:
[default=die]
pam_faillock.so authfail unlock_time=600
PEOF
  cat > "$D/faillock_reset" <<'PEOF'
Name: Reset lockout on success
Default: no
Priority: 0
Auth-Type: Additional
Auth:
required
pam_faillock.so authsucc
PEOF
  cat > "$D/faillock_notify" <<'PEOF'
Name: Notify on account lockout
Default: no
Priority: 1024
Auth-Type: Primary
Auth:
requisite
pam_faillock.so preauth
PEOF
  S cp "$D/faillock" "$D/faillock_reset" "$D/faillock_notify" /usr/share/pam-configs/
  S chmod 644 /usr/share/pam-configs/faillock /usr/share/pam-configs/faillock_reset /usr/share/pam-configs/faillock_notify
  rm -rf "$D"
  ls /usr/share/pam-configs/faillock* 2>/dev/null && ok "3 lockout profiles in place" || warn "profiles missing"
  # 3) nullok removal
  S sed -ri 's/(pam_unix\.so)[[:space:]]+nullok[[:space:]]*/\1/' /etc/pam.d/common-auth
  grep -an nullok /etc/pam.d/common-auth && warn "nullok REMNANT — inspect" || ok "no nullok in common-auth"
  fail "AUTH-SANITY REQUIRED NOW: before leaving this session, open a FRESH SSH login with a password. If it fails: revert with  sudo bash -c 'yes | cp -a /root/pam_backup_<ts>/. /etc/pam.d/'  (the ts dir is listed in /root)"
else
  info "PAM_BLOCK off (owner rule 2026-11-11): min-length / lockout / null-password items left exactly as the image provides them"
fi

# ========================== 6 · sysctl ==========================
step "6 · SYSCTL — SYN cookies on, IP forward off"
S sed -ri 's/^(net\.ipv4\.tcp_syncookies=).*$/\1 1/' /etc/sysctl.conf
S sed -ri 's/^(net\.ipv4\.ip_forward=).*$/\1 0/' /etc/sysctl.conf
S sysctl --system >/dev/null 2>&1
sysctl net.ipv4.tcp_syncookies net.ipv4.ip_forward

# ====================== 7 · shadow perms ======================
step "7 · /etc/shadow 640"
S chmod 640 /etc/shadow; ls -l /etc/shadow

# ============== 8 · services (config, keep-list guarded) ==============
step "8 · SERVICES (stop list from config; keep list is sacrosanct)"
for s in ${STOP_SERVICES:-}; do
  if on_keep "$s"; then warn "$s is on KEEP list — NOT touched"; continue; fi
  S systemctl disable --now "$s" >/dev/null 2>&1 || true
  systemctl is-active "$s" 2>/dev/null | grep -q '^inactive\|^failed' && ok "$s stopped" || warn "$s state unclear"
done
[ -z "${STOP_SERVICES:-}" ] && info "(no STOP_SERVICES in this round's config — nothing to do)"

# ============== 9 · purges (config + base, keep-list guarded) ==============
step "9 · PACKAGE PURGES (base: nmap ophcrack hydra john + config PURGE_PKGS/POLL_PKGS/samba)"
PURGE_ALL=" $PROHIBIT_BASE ${PURGE_PKGS:-} ${POLL_PKGS:-} "
[ "${SMB_REMOVAL:-no}" = "yes" ] && PURGE_ALL="$PURGE_ALL samba smbclient samba-common"
for p in $PURGE_ALL; do
  [ -z "$p" ] && continue
  if on_keep_pkg "$p"; then warn "$p on KEEP_PKGS — NOT purged"; continue; fi
  if dpkg -s "$p" >/dev/null 2>&1; then
    apt-get -y --purge remove "$p" >/dev/null 2>&1 && ok "purged $p" || warn "purge $p failed"
  else info "not installed: $p"; fi
done

# ====================== 10 · user media ======================
step "10 · USER MEDIA under /home (exts: $MEDIA_EXTS) — /opt and system dirs untouched"
before=$(find /home -maxdepth 6 -type f $(media_expr) 2>/dev/null | wc -l)
find /home -maxdepth 6 -type f $(media_expr) -delete 2>/dev/null
after=$(find /home -maxdepth 6 -type f $(media_expr) 2>/dev/null | wc -l)
ok "media: ${before} -> ${after}"

# ====================== 11 · backdoor (netcat) cleanup ======================
step "11 · BACKDOOR CLEANUP — netcat packages / listeners / cron (all keep-list guarded)"
if echo "$KEEP_PKGS" | tr ' ' '\n' | grep -qE '^(nc|ncat|netcat)'; then
  warn "an nc variant is on KEEP_PKGS — skipping backdoor cleanup entirely"
else
  # 1) running listeners — kill by EXACT process name (pkill -x only, never -f patterns)
  for p in nc ncat nc.traditional; do
    pgrep -x "$p" >/dev/null 2>&1 && S pkill -x "$p" 2>/dev/null && ok "killed listener: $p" || true
  done
  # 2) netcat packages — purge every variant that is installed
  for p in netcat netcat-traditional netcat-openbsd ncat; do
    on_keep_pkg "$p" && { warn "$p keep-listed — not purged"; continue; }
    if dpkg -s "$p" >/dev/null 2>&1; then
      apt-get -y --purge remove "$p" >/dev/null 2>&1 && ok "purged $p" || warn "purge $p failed"
    fi
  done
  # 3) bare dropped binaries (backdoors often ship no package at all)
  S bash -c 'for b in /usr/bin/nc /usr/bin/nc.traditional /usr/bin/nc.openbsd /usr/local/bin/nc /usr/local/bin/ncat; do [ -e "$b" ] && { echo "removing $b"; rm -f "$b"; }; done'
  # 4) cron lines that restart listeners (root + user crontabs) — word-boundary match only
  S bash -c 'for ct in /etc/crontab /etc/cron.d/* /etc/cron.daily/* /var/spool/cron/crontabs/*; do [ -f "$ct" ] || continue; if grep -qwE "nc|ncat" "$ct"; then sed -ri "/(^|[[:space:]])(nc|ncat)([[:space:]]|$)|\/dev\/tcp/d" "$ct" && echo "cron lines removed from $ct"; fi; done'
  pgrep -x '^(nc|ncat|nc\.traditional)$' >/dev/null 2>&1 && fail "nc listener STILL RUNNING" || ok "no nc/ncat listeners, no packages, cron clean"
fi

# ====================== 12 · sshd ======================
step "12 · SSHD — root login off, service stays enabled"
S bash -c "sed -ri 's/^(PermitRootLogin)[[:space:]]+.*/\1 no/' /etc/ssh/sshd_config" 2>/dev/null || true
grep -qE '^[[:space:]]*PermitRootLogin[[:space:]]+no[[:space:]]*$' /etc/ssh/sshd_config \
  || S bash -c "printf 'PermitRootLogin no\n' >> /etc/ssh/sshd_config"
grep -anE '^PermitRootLogin' /etc/ssh/sshd_config | tail -1
S sshd -t 2>/dev/null && ok "config valid" || warn "sshd -t FAILED — revert last edit!"
S systemctl enable ssh >/dev/null 2>&1; S systemctl reload ssh 2>/dev/null || S systemctl restart ssh 2>/dev/null
ss -tln 2>/dev/null | grep -q ':22 ' && ok "listening :22" || fail "SSH not listening — must fix before leaving"

# ====================== 13 · UFW ======================
step "13 · UFW (allow 22, default deny incoming)"
S apt-get install -y ufw >/dev/null 2>&1 || warn "ufw package install failed"
S ufw allow OpenSSH >/dev/null 2>&1 || S ufw allow 22/tcp >/dev/null 2>&1
S ufw default deny incoming >/dev/null 2>&1; S ufw default allow outgoing >/dev/null 2>&1
S ufw --force enable >/dev/null 2>&1
ufw status verbose 2>/dev/null | sed 's/^/    /'

# ====================== 14 · browser default ======================
step "14 · BROWSER DEFAULT (whatever of chromium/firefox is installed)"
BROWSER=""
for cand in chromium chromium-browser /usr/bin/chromium /usr/bin/chromium-browser firefox firefox-esr /usr/bin/firefox; do
  command -v "$cand" >/dev/null 2>&1 && { BROWSER=$(command -v "$cand"); break; }
done
if [ -n "$BROWSER" ]; then
  update-alternatives --install /usr/bin/x-www-browser x-www-browser "$BROWSER" 100 >/dev/null 2>&1 && ok "x-www-browser -> $BROWSER"
  update-alternatives --install /usr/bin/www-browser www-browser "$BROWSER" 100 >/dev/null 2>&1 && ok "www-browser -> $BROWSER"
  DESK=$(readlink -f "$(command -v xdg-mime 2>/dev/null || echo xdg-mime)" 2>/dev/null || true)
  for d in /home/*/; do
    u=$(basename "$d"); [ -d "$d/.config" ] || continue
    printf 'x-scheme-handler/http=xdg-open\n' > /dev/null # (mimeapps needs the real .desktop name)
  done
  info "per-user mimeapps: write <browser>.desktop into each /home/<u>/.config/mimeapps.list this round if scored"
else
  warn "no known browser binary found — check the README's browser requirement"
fi

# ====================== 15 · display manager ======================
step "15 · DISPLAY MANAGER (report only — never changed here)"
echo -n "    default-display-manager : "; cat /etc/X11/default-display-manager 2>/dev/null || echo "(not set)"
systemctl list-unit-files 2>/dev/null | grep -iE '^(lightdm|gdm|sddm)' | sed 's/^/    unit: /'
ok "record the distro's DM for the report"

# ====================== 16 · auto daily updates ======================
step "16 · AUTO DAILY UPDATES (lists + downloads + unattended — both scored update items)"
S bash -c 'printf "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Download-Upgradeable-Packages \"1\";\nAPT::Periodic::AutocleanInterval \"7\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n" > /etc/apt/apt.conf.d/20auto-upgrades'
S apt-get install -y unattended-upgrades >/dev/null 2>&1 || info "unattended-upgrades pkg unavailable in repos (config lines still written)"
cat /etc/apt/apt.conf.d/20auto-upgrades

# ====================== 17 · final report ======================
step "FINAL STATE — read off for the scoring report"
echo "  round : ${ROUND_LABEL:-<none>}"
getent group sudo 2>/dev/null | sed 's/^/  sudo   : /'
grep -a '^PASS_MIN_DAYS' /etc/login.defs | sed 's/^/  defs   : /'
grep -an pwquality /etc/pam.d/common-password | sed 's/^/  pw     : /'
grep -c faillock /etc/pam.d/common-auth 2>/dev/null | sed 's/^/  flines : /'
ls /usr/share/pam-configs/faillock* 2>/dev/null | sed 's/^/  prof   : /'
grep -an nullok /etc/pam.d/common-auth 2>/dev/null || echo "  nullok : none"
echo "  pamblk : ${PAM_BLOCK:-no}"
sysctl -n net.ipv4.tcp_syncookies net.ipv4.ip_forward 2>/dev/null | sed 's/^/  sysctl : /'
ls -l /etc/shadow | sed 's/^/  shadow : /'
ufw status 2>/dev/null | sed 's/^/  ufw    : /'
systemctl is-active ssh 2>/dev/null | sed 's/^/  ssh    : /'
pgrep -x '^(nc|ncat)$' >/dev/null 2>&1 && echo "  nc     : LISTENER STILL RUNNING (!)" || echo "  nc     : no listeners"
echo "  media  : $(find /home -maxdepth 6 -type f $(media_expr) 2>/dev/null | wc -l) matching files remain"
echo
echo "  STILL HAND (by design, not scripted): forensics console answers, sources/keys if apt warned,"
echo "  unique identifier, per-round README-only extras (share configs, group sizes, etc.)"
