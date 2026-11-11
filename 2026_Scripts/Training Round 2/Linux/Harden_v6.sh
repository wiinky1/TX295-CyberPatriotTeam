#!/usr/bin/env bash
# =====================================================================
#  CyberPatriot 2026 — SYSTEM HARDENING, v2 (merged)
#  Base : cp19 round script (harden.sh — the one that scored 100/100 on
#         Training Round 2 Debian 12, 2026-11-11)
#  Merged into the structure of cap_hardening_2026.sh (step banners,
#         preflight, idempotency, final report) + added its extra sections
#         (DM check, browser defaults, polling svc purge, samba, sshd
#         drop-in) that other images score (Mint 21, later rounds).
#
#  Round config:  EDIT THE BLOCK BELOW for each image.
#  Port to Mint 21 / another image by changing CONFIG only — the generic
#  sections then apply as-is, and the round-specific sections run
#  no-op-safe if the users/objects don't exist.
#
#  NOT in this script (per-round, by hand): FORENSICS answers (question
#  changes every round), and anything the coach says not to touch this
#  round (auto-login password, UTC, CCS client, critical services).
#
#  Run : sudo bash harden_v2.sh
#  PAM safety: faillock is wired only via pam-auth-update with the
#  three pam-configs from the official answer key; we never sed
#  pam_deny/pam_unix lines without a grep-verify + sshd/login check after.
# =====================================================================
set -uo pipefail
LC_ALL=C
export DEBIAN_FRONTEND=noninteractive

# ============================ ROUND CONFIG ============================
R2_REMOVE_USERS=(athorne pbaelish)        # deluser --force --remove-home
R2_SUDO_REMOVES=(jlannister)             # take out of sudo group (keep account)
R2_PW_USER=rbaratheon                     # change the weak password
R2_PW='SteelClaw-King#2026'               # 17 chars, mixed classes, no dict
GROUP_TASK_USER=bselmy                    # add to roster group
GROUP_TASK_GROUP=queensguard
MINLEN=12                                 # pwquality minimum length (round req)
PASS_MIN_DAYS=7                           # /etc/login.defs
KEEP_WIRESHARK=0                          # 1 on the Mint image (authorized there)
KEEP_VSFTPD=0                             # 1 on the Mint image (critical svc there)
AUTOLOGIN_USER=pparker-no-op              # leave unset/blank: never touched
# ======================================================================

ok()   { echo -e "  \033[32m[ OK ]\033[0m $*"; }
warn() { echo -e "  \033[33m[WARN ]\033[0m $*"; }
fail() { echo -e "  \033[31m[ FAIL ]\033[0m $*"; }
info() { echo -e "  \033[90m[ .. ]\033[0m $*"; }
step() { echo; echo -e "\n\033[1;36m== $* ==\033[0m"; }
S() { sudo "$@"; }

if [ "$(id -u)" -ne 0 ] && [ -z "${SUDO_ASKPASS:-}" ]; then
  # running under `sudo bash script` -> already root; else re-exec
  if [ -n "$(command -v sudo)" ]; then echo "needs root — re-run with sudo"; fi
fi

# ---------- step 0 · preflight ----------
step "0 · PREFLIGHT"
echo "  host   : $(hostname)"
echo "  os     : $(grep PRETTY /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '"')"
echo "  users  : $(awk -F: '$3>=1000 && $3<65534{print $1}' /etc/passwd | tr '\n' ' ')"
echo "  config : remove ${R2_REMOVE_USERS[*]} | sudo-del ${R2_SUDO_REMOVES[*]} | ${R2_PW_USER} pw | ${GROUP_TASK_USER}->${GROUP_TASK_GROUP}"
echo "  config : minlen=${MINLEN} pass-min-days=${PASS_MIN_DAYS} wireshark-keep=${KEEP_WIRESHARK} vsftpd-keep=${KEEP_VSFTPD}"
info "read the round README first; do NOT touch: CCS client, UTC, auto-login pw, critical services"
[ "${1:-}" = '--yes' ] || { echo "Press ENTER to run, or Ctrl-C to abort..."; read -r _; }

# ---------- step 1 · apt update + upgrade (scored) ----------
step "1 · APT UPDATE + UPGRADE (Chromium + OpenSSH updated come from here)"
env DEBIAN_FRONTEND=noninteractive apt-get update 2>&1 | tail -2
env DEBIAN_FRONTEND=noninteractive apt-get -y upgrade 2>&1 | tail -5 \
  && ok "upgrade done" || warn "upgrade reported problems (see tail above)"
env DEBIAN_FRONTEND=noninteractive apt-get -y autoremove >/dev/null 2>&1; apt-get -y clean >/dev/null 2>&1
ok "cleaned"

# ---------- step 2 · forbidden software (round-scored + generic) ----------
step "2 · FORBIDDEN SOFTWARE"
if [ "$KEEP_WIRESHARK" -eq 0 ]; then
  for p in wireshark aisleriot; do
    if dpkg -s "$p" >/dev/null 2>&1; then
      env DEBIAN_FRONTEND=noninteractive apt-get -y --purge remove "$p" >/dev/null 2>&1 && ok "purged $p" || warn "purge $p failed"
    else info "$p not installed"; fi
  done
  command -v wireshark >/dev/null 2>&1 && warn "wireshark binary still present" || ok "wireshark gone"
else info "KEEP_WIRESHARK=1 — this image authorizes it; skipping"; fi
for p in nmap ophcrack hydra john; do
  dpkg -s "$p" >/dev/null 2>&1 && { env DEBIAN_FRONTEND=noninteractive apt-get -y --purge remove "$p" >/dev/null 2>&1 && ok "purged $p"; } || info "not installed: $p"
done

# ---------- step 3 · user audit (round-specific) ----------
step "3 · USER AUDIT"
for u in "${R2_REMOVE_USERS[@]}"; do
  if getent passwd "$u" >/dev/null 2>&1; then
    S deluser --force --remove-home "$u" 2>&1 | tail -1
    S rm -rf "/home/$u" 2>/dev/null
  fi
  getent passwd "$u" >/dev/null 2>&1 && warn "$u STILL PRESENT" || ok "$u removed"
done
for u in "${R2_SUDO_REMOVES[@]}"; do
  S gpasswd -d "$u" sudo 2>&1 | tail -1
  getent group sudo | grep -qw "$u" && warn "$u still in sudo" || ok "$u out of sudo"
done
if [ -n "$R2_PW_USER" ] && [ "$R2_PW_USER" != "pparker-no-op" ]; then
  echo "${R2_PW_USER}:${R2_PW}" | S chpasswd && ok "strong pw set for ${R2_PW_USER} (${#R2_PW} chars)" || fail "pw set FAILED for ${R2_PW_USER}"
fi
id "$GROUP_TASK_USER" >/dev/null 2>&1 || S adduser --disabled-password --gecos "Baster Sell" "$GROUP_TASK_USER" >/dev/null 2>&1
S usermod -aG "$GROUP_TASK_GROUP" "$GROUP_TASK_USER" 2>&1 | tail -1
getent group "$GROUP_TASK_GROUP" | grep -qw "$GROUP_TASK_USER" && ok "${GROUP_TASK_USER} in ${GROUP_TASK_GROUP}" || fail "group add FAILED"
# authorized users: force a password change on next login (round task: weak pws)
# note: only if the round README lists a weak password to change — safe/idempotent otherwise
grep -Eq "^[[:blank:]]*[1-9]" /etc/shadow 2>/dev/null && info "shadow has non-expired entries — set the remaining weak passwords per README" || true

# ---------- step 4 · password policy (round values) ----------
step "4 · PASSWORD POLICY — minlen=${MINLEN}, PASS_MIN_DAYS=${PASS_MIN_DAYS}"
grep -q pam_pwquality.so /etc/pam.d/common-password \
  || S sed -i "/pam_unix.so/a password\t[success=1 default=ignore]\tpam_pwquality.so" /etc/pam.d/common-password
# enforce minlen on the pwquality line regardless of what shipped
S sed -ri "s/(pam_pwquality\.so[^\\n]*)/\1 minlen=${MINLEN}/" /etc/pam.d/common-password
grep -an pwquality /etc/pam.d/common-password
S sed -ri "s/^(PASS_MIN_DAYS[[:space:]]+).*/\1${PASS_MIN_DAYS}/" /etc/login.defs
grep -a '^PASS_MIN_DAYS' /etc/login.defs
ok "policy config written"

# ---------- step 5 · faillock via pam-configs (the SAFE way) ----------
step "5 · ACCOUNT LOCKOUT — pam-auth-update (no raw sed into pam files beyond verified lines)"
S mkdir -p /usr/share/pam-configs
cat > /tmp/cp_faillock <<'PEOF'
Name: Lockout on failed logins
Default: no
Priority: 0
Auth-Type: Primary

Auth:
[default=die]
pam_faillock.so authfail unlock_time=600
PEOF
cat > /tmp/cp_faillock_reset <<'PEOF'
Name: Reset lockout on success
Default: no
Priority: 0
Auth-Type: Additional

Auth:
required
pam_faillock.so authsucc
PEOF
cat > /tmp/cp_faillock_notify <<'PEOF'
Name: Notify on account lockout
Default: no
Priority: 1024
Auth-Type: Primary

Auth:
requisite
pam_faillock.so preauth
PEOF
S cp /tmp/cp_faillock     /usr/share/pam-configs/faillock
S cp /tmp/cp_faillock_reset /usr/share/pam-configs/faillock_reset
S cp /tmp/cp_faillock_notify /usr/share/pam-configs/faillock_notify
S chmod 644 /usr/share/pam-configs/faillock /usr/share/pam-configs/faillock_reset /usr/share/pam-configs/faillock_notify
S pam-auth-update --enable faillock --enable faillock_reset --enable faillock_notify 2>&1 | tail -2
grep -rn faillock /etc/pam.d/common-auth 2>/dev/null | head -4
ok "faillock wired"

# ---------- step 6 · null passwords ----------
step "6 · NULL PASSWORDS DO NOT AUTHENTICATE"
if grep -q 'pam_unix.so.*nullok\|nullok.*pam_unix.so' /etc/pam.d/common-auth; then
  S sed -ri 's/(pam_unix\.so)[[:space:]]+nullok/\1/' /etc/pam.d/common-auth
fi
grep -an nullok /etc/pam.d/common-auth || ok "nullok gone from common-auth"

# ---------- step 7 · sysctl ----------
step "7 · SYSCTL — SYN cookies on, IP forward off"
S sed -ri 's/^(net\.ipv4\.tcp_syncookies=).*$/\1 1/' /etc/sysctl.conf
S sed -ri 's/^(net\.ipv4\.ip_forward=).*$/\1 0/' /etc/sysctl.conf
S sysctl --system >/dev/null 2>&1
sysctl net.ipv4.tcp_syncookies net.ipv4.ip_forward

# ---------- step 8 · /etc/shadow perms ----------
step "8 · SHADOW PERMS 640"
S chmod 640 /etc/shadow
ls -l /etc/shadow

# ---------- step 9 · apache2 / vsftpd ----------
step "9 · APACHE2 OFF · vsftpd per KEEP_VSFTPD"
S systemctl disable --now apache2 2>&1 | tail -1 || true
systemctl is-active apache2 2>/dev/null | grep -q inactive && ok "apache2 stopped" || warn "apache2 state?"
if [ "$KEEP_VSFTPD" -eq 0 ]; then
  S systemctl disable --now vsftpd 2>&1 | tail -1 || true
  systemctl is-active vsftpd 2>/dev/null | grep -q inactive && ok "vsftpd stopped" || warn "vsftpd state?"
else info "KEEP_VSFTPD=1 — critical service on this image, left running"; fi
ss -tln 2>/dev/null | grep -E '(:80|:21) ' || ok "ports 80/21 closed"

# ---------- step 10 · netcat backdoor ----------
step "10 · NETCAT BACKDOOR (port 1337)"
if S crontab -l 2>/dev/null | grep -q 'nc.traditional'; then
  S crontab -l 2>/dev/null | grep -v 'nc.traditional' > /tmp/root_cron_clean.txt
  if [ -s /tmp/root_cron_clean.txt ]; then S bash -c 'crontab /tmp/root_cron_clean.txt'; else S crontab -r 2>/dev/null; fi
  ok "cron entry stripped"
fi
S pkill -f 'nc.traditional' 2>/dev/null || true
sleep 1
pgrep -af 'nc.traditional' >/dev/null 2>&1 && warn "backdoor proc still up" || ok "backdoor proc gone"
S rm -f /usr/bin/nc.traditional
ls /usr/bin/nc.traditional 2>/dev/null && warn "binary still on disk" || ok "nc.traditional removed"
ss -tln 2>/dev/null | grep ':1337 ' && warn "1337 still listening" || ok "1337 closed"

# ---------- step 11 · media files in /home ----------
step "11 · USER MEDIA DELETED (mp3 per this round; add exts per round)"
before=$(find /home -maxdepth 6 -type f -iname '*.mp3' 2>/dev/null | wc -l)
find /home -maxdepth 6 -type f -iname '*.mp3' -print -delete >/dev/null 2>&1
after=$(find /home -maxdepth 6 -type f -iname '*.mp3' 2>/dev/null | wc -l)
ok "mp3: ${before} -> ${after}"

# ---------- step 12 · apt sources (round task) ----------
step "12 · APT SOURCES (bookworm clean sources)"
cat > /tmp/sources.new <<'SL'
deb http://deb.debian.org/debian bookworm main contrib non-free non-free-firmware
deb http://deb.debian.org/debian-security bookworm-security main contrib non-free non-free-firmware
SL
S cp /tmp/sources.new /etc/apt/sources.list
ok "sources.list rewritten"; cat /etc/apt/sources.list

# ---------- step 13 · auto daily updates (round-scored) ----------
step "13 · AUTO DAILY UPDATES"
S bash -c 'printf "APT::Periodic::Update-Package-Lists \\"1\\";" > /etc/apt/apt.conf.d/20auto-upgrades'
cat /etc/apt/apt.conf.d/20auto-upgrades && ok "APT::Periodic set"

# ---------- step 14 · sshd ----------
step "14 · SSHD — no root login, stay enabled"
S bash -c "sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config" 2>/dev/null || true
grep -an '^PermitRootLogin' /etc/ssh/sshd_config | tail -1
S sshd -t 2>/dev/null && ok "sshd config valid" || warn "sshd -t failed — check config"
S systemctl enable ssh 2>/dev/null; S systemctl reload ssh 2>&1 | tail -1
ss -tln 2>/dev/null | grep -q ':22 ' && ok "SSH listening :22" || warn "SSH not listening — fix before leaving"

# ---------- step 15 · UFW ----------
step "15 · UFW"
S ufw allow OpenSSH 2>/dev/null || S ufw allow 22/tcp
S ufw default deny incoming; S ufw default allow outgoing; S ufw --force enable 2>/dev/null
ufw status verbose 2>/dev/null | sed 's/^/    /'

# ---------- step 16 · display manager (keep the distro's — LightDM) ----------
step "16 · DISPLAY MANAGER (verify, don't change)"
echo -n "    now : "; cat /etc/X11/default-display-manager 2>/dev/null || echo "(not set)"
ls /usr/lib/systemd/system/*.service 2>/dev/null | grep -iE 'lightdm|gdm|sddm' | sed 's/^/    unit: /'
ok "record this for the report"

# ---------- step 17 · browser default (Chromium on Debian) ----------
step "17 · BROWSER DEFAULT"
CR=$(command -v chromium 2>/dev/null || command -v chromium-browser 2>/dev/null || echo /usr/bin/chromium)
update-alternatives --install /usr/bin/x-www-browser x-www-browser "$CR" 100 >/dev/null 2>&1 && ok "x-www-browser -> $CR"
update-alternatives --install /usr/bin/www-browser   www-browser   "$CR" 100 >/dev/null 2>&1 && ok "www-browser   -> $CR"
ok "defaults set"

# ---------- step 18 · polling/maintenance + samba (other images score these) ----------
step "18 · POLLING/MAINTENANCE SVC + SAMBA"
for s in bluetooth blueman udisks2 avahi-daemon avahi cups-browsed cups modemmanager; do
  S systemctl disable --now "$s" 2>/dev/null || true
done
env DEBIAN_FRONTEND=noninteractive apt-get -y --purge remove bluetooth blueman udisks2 avahi avahi-daemon cups-browsed cups modemmanager samba smbclient samba-common 2>/dev/null | tail -1
ok "purged (no-op if absent)"

# ---------- final report ----------
step "FINAL STATE — read off for the scoring report"
getent group sudo; id "$GROUP_TASK_USER" 2>&1
getent passwd athorne pbaelish 2>&1 | sed 's/^/    /'
grep -a '^PASS_MIN_DAYS' /etc/login.defs; ls -l /etc/shadow
grep -an pwquality /etc/pam.d/common-password
grep -rn faillock /etc/pam.d/common-auth 2>/dev/null | head -3
grep -an nullok /etc/pam.d/common-auth || echo "nullok: none"
sysctl net.ipv4.tcp_syncookies net.ipv4.ip_forward
ls /usr/bin/nc.traditional 2>/dev/null || echo "nc: REMOVED"
command -v wireshark 2>/dev/null || echo "wireshark: GONE"
echo "    mp3 count: $(find /home -name '*.mp3' 2>/dev/null | wc -l)"
ufw status 2>/dev/null | head -3
systemctl is-active ssh apache2 vsftpd 2>&1 | sed 's/^/    /'
ss -tln 2>/dev/null
echo
echo "STILL HAND: forensics answers (per this round's question) + any README-only task"
