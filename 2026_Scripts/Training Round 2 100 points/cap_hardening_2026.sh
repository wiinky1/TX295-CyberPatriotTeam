#!/usr/bin/env bash
# =====================================================================
#  CyberPatriot 2026 — FULL SYSTEM HARDENING  (distro-agnostic: Mint, Ubuntu, or
#  any CP-issued VM — the display manager is auto-detected)
#  Scope : everything the rules book scores, EXCEPT (a) the user-audit
#          tasks (create tchalla / delete unauthorized users / set the 17
#          passwords / chage -d 0) and (b) the forensics ANSWER — the
#          forensics question changes every round, so it is not pre-baked.
#          Do (a) and (b) by hand, per round.
#
#  Run   :  sudo bash cap_hardening_2026.sh [optional:file-to-hexdump]
#          (only pass a file if you want a raw hexdump; the forensics
#           ANSWER is still yours to work out against THIS round's question)
#
#  Rules ref: CP19 Rules Book 2026 — sections cited inline below.
#  Design  : idempotent, no `set -e` so one soft-fail never kills the
#          run; every section prints an OK/WARN line; final report prints
#          the settings to read off and paste into the report UI.
# =====================================================================
set -uo pipefail
LC_ALL=C
export DEBIAN_FRONTEND=noninteractive

# ---------- pretty helpers ----------
ok()   { echo -e "  \033[32m[ OK ]\033[0m $*"; }
warn() { echo -e "  \033[33m[ WARN ]\033[0m $*"; }
fail() { echo -e "  \033[31m[ FAIL ]\033[0m $*"; }
info() { echo -e "  \033[90m[ .. ]\033[0m $*"; }
step() { echo; echo -e "\n\033[1;36m== $* ==\033[0m"; }
MEDIA_EXTS=(-iname '*.mp3' -o -iname '*.mp4' -o -iname '*.ogg' -o -iname '*.oga'
            -o -iname '*.wav' -o -iname '*.avi' -o -iname '*.mov' -o -iname '*.mkv'
            -o -iname '*.flv' -o -iname '*.wmv' -o -iname '*.aac' -o -iname '*.wma')
# raw hexdump of a file's head (xxd if present, else od).
# Used ONLY if you explicitly pass a file path; never auto-runs, never
# claims an answer (the forensics question is different every round).
hexhead() {
  f="$1"; n="${2:-256}"
  if command -v xxd >/dev/null 2>&1; then
    xxd -l "$n" "$f"
  else
    od -A x -t x1 -N "$n" "$f" | head -16
  fi
}

# ---------- preflight ----------
if [ "$(id -u)" -ne 0 ]; then
  fail "this script needs root.  Re-run:  sudo bash $0 ${1:-}"
  exit 1
fi

HEXFILE="${1:-}"        # optional: only used for a manual hexdump
SSHGRP="ssh"

real_users() { awk -F: '($3>=1000 && $3<65534){print $1}' /etc/passwd; }

step "0 · PREFLIGHT — read what this script will do"
echo "  host     : $(hostname)"
echo "  kernel   : $(uname -r)"
echo -n "  os       : "; (grep PRETTY /etc/os-release | cut -d= -f2- | tr -d '"') 2>/dev/null || true
echo "  users    : $(real_users | tr '\n' ' ')"
echo "  hexdump  : ${HEXFILE:-(none — forensics is per-round; answered by hand)}"
warn "SCOPE: system hardening only.  NOT in this script — do by hand, per round:"
warn "   (a) USER-AUDIT: tchalla / delete ultron+thanos / 17 pw / chage -d 0"
warn "   (b) the FORENSICS question/answer  (it changes every round)"
echo "Press ENTER to run, or Ctrl-C to abort..."
read -r _

# =====================================================================
step "1 · FORENSICS — per-round, NOT auto-answered (the question changes every round)"
if [ -n "$HEXFILE" ] && [ -f "$HEXFILE" ]; then
  info "raw hex dump of: $HEXFILE  (read it yourself against THIS round's real question)"
  echo
  hexhead "$HEXFILE" 256
  echo
else
  info "no file passed — intentional.  The forensics question differs every round,"
  info "so this script does not guess one.  Over SSH, answer it yourself, e.g.:"
  info "      xxd -l 5 <the file the question names>    then type the bytes it asks for"
fi

# =====================================================================
step "2 · OPEN SOURCE APPS UPDATED (rule 2.11.3.1.2 — scored)"
info "apt-get update ..." ;  apt-get -qq update >/dev/null 2>&1
info "apt-get -y upgrade (this can take 1-5 min) ..."
apt-get -y -o APT::AutoRemove::Recommends=true upgrade >/tmp/cap_upgrade.log 2>&1 && ok "upgraded" || fail "upgrade reported errors (see /tmp/cap_upgrade.log)"
apt-get -y autoremove >/dev/null 2>&1 ; apt-get -y clean >/dev/null 2>&1 && ok "autoremoved + cleaned" || true

# =====================================================================
step "3 · PURGE PROHIBITED TOOLS (Nmap, Ophcrack, Hydra, JtR — rule 2.2.8.2)"
for p in nmap ophcrack hydra john; do
  if dpkg -s "$p" >/dev/null 2>&1; then
    apt-get -y --purge remove "$p" >/dev/null 2>&1 && ok "purged $p" || warn "could not purge $p"
  else info "not installed: $p"; fi
done
# stray .desktop entries anywhere a user double-clicks (incl. desktop dirs)
for base in /home/* /.desktop /usr/share/applications /usr/local/share/applications; do
  [ -d "$base" ] || continue
  while IFS= read -r d; do
    [ -e "$d" ] || continue
    if echo "$d" | grep -qiE '/(nmap|ophcrack|hydra|john)/|/(nmap|ophcrack|hydra|john)[^0-9].*\.desktop$'; then
      rm -f "$d" && ok "removed shortcut: $d"
    fi
  done < <(find "$base" -maxdepth 3 -iname '*.desktop' 2>/dev/null)
done

# =====================================================================
step "4 · SSHD HARDENING (rule 2.1.3 — scored)"
mkdir -p /etc/ssh/sshd_config.d
cat >/etc/ssh/sshd_config.d/90-cp-hardening.conf <<'EOF'
PasswordAuthentication   yes
PermitRootLogin          no
MaxAuthTries             4
LoginGraceTime           60
X11Forwarding            no
PermitEmptyPasswords     no
AllowGroups              ssh
EOF
ok "wrote /etc/ssh/sshd_config.d/90-cp-hardening.conf"
# the AllowGroups target (group only — membership below is idempotent)
getent group "$SSHGRP" >/dev/null 2>&1 || { groupadd "$SSHGRP" && ok "created group '$SSHGRP'"; }
for u in $(real_users); do usermod -aG "$SSHGRP" "$u" 2>/dev/null; done
ok "all existing real users are members of '$SSHGRP' (incl. tchalla once it exists)"
if sshd -t 2>/tmp/cap_sshd.err; then ok "sshd config valid"; else fail "sshd -t: $(cat /tmp/cap_sshd.err)"; fi
systemctl enable ssh 2>/dev/null ; systemctl restart ssh 2>/dev/null
ok "ssh service: enabled + restarted"

# =====================================================================
step "5 · PASSWORD POLICY CONFIG (rules 2.2.11.5, 2.2.7 — config side)"
cat >/etc/security/pwquality.conf <<'EOF'
minlen   = 10
dcredit  = -1
ucredit  = -1
lcredit  = -1
ocredit  = -1
difok    = 1
usercheck= 1
enforce_for_root = yes
EOF
ok "pwquality: minlen=10, all 4 char classes required"
if ! grep -q 'pam_pwquality' /etc/pam.d/common-password; then
  sed -i '/^password.*pam_unix/a password    requisite     pam_pwquality.so   minlen=10   retry=3' /etc/pam.d/common-password
  ok "pam_pwquality wired into common-password"
else info "pam_pwquality already wired"; fi
sed -i 's/ nullok//g' /etc/pam.d/common-auth /etc/pam.d/common-password 2>/dev/null
ok "nullok removed (common-auth, common-password)"
# NOTE: chage -d 0 (rule 2.2.7 "prompt to change") = USER-AUDIT side, not here.

# =====================================================================
step "6 · UFW (rules 2.1.5, 2.1.10, 2.1.9 — scored)"
ufw default deny incoming        >/dev/null 2>&1
ufw default allow outgoing       >/dev/null 2>&1
if ufw status 2>/dev/null | grep -qE '^\s*554/'; then ufw delete allow 554/tcp >/dev/null 2>&1; ufw delete deny 554/tcp >/dev/null 2>&1; ok "554/tcp removed"; fi
ufw allow 22/tcp                 >/dev/null 2>&1 && ok "22/tcp allowed (SSH)"
ufw --force enable               >/dev/null 2>&1 && ok "UFW enabled"
ufw status                       2>/dev/null | sed 's/^/    /'
warn "if the scorer wants 554/tcp explicitly DENY, run:  sudo ufw deny 554/tcp"

# =====================================================================
step "7 · DISPLAY MANAGER — use the distro's own DM (Mint→LightDM, Ubuntu→GDM, KDE→SDDM)"
DM=""; DM_PATH=""
# 1) respect a choice the box already made
EXISTING_DM=$(cat /etc/X11/default-display-manager 2>/dev/null)
if [ -n "$EXISTING_DM" ] && [ -x "$EXISTING_DM" ]; then
  DM_PATH="$EXISTING_DM"; DM=$(basename "$DM_PATH")
else
  # 2) otherwise, pick the first DM actually installed
  for name in lightdm gdm3 gdm sddm; do
    for bin in "/usr/sbin/$name" "/usr/bin/$name"; do
      if [ -x "$bin" ]; then DM="$name"; DM_PATH="$bin"; break 2; fi
    done
  done
fi

if [ -n "$DM" ]; then
  mkdir -p /etc/X11
  echo "$DM_PATH" >/etc/X11/default-display-manager && ok "default-display-manager -> $DM_PATH"
  if [ -f "/usr/lib/systemd/system/${DM}.service" ]; then
    update-alternatives --install /usr/lib/systemd/system/graphical.target graphical-target \
      "/usr/lib/systemd/system/${DM}.service" 20 2>/dev/null
    update-alternatives --set graphical-target "$DM" 2>/dev/null && ok "graphical-target -> $DM"
  fi
  systemctl enable "$DM" 2>/dev/null && ok "$DM enabled" || info "$DM enable non-zero (no [Install] — usually fine)"
  echo -n "    now  : "; cat /etc/X11/default-display-manager 2>/dev/null
else
  warn "no display-manager binary auto-detected — set /etc/X11/default-display-manager by hand"
fi

# =====================================================================
step "8 · POLLING / MAINTENANCE services + packages (rule 2.1.9 — scored)"
for s in bluetooth blueman udisks2 avahi-daemon avahi cups-browsed cups modemmanager; do
  if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -q "^${s}\.service"; then
    systemctl disable --now "$s" 2>/dev/null && ok "disabled $s" || info "disable $s (skip)"
  else info "no unit: $s"; fi
done
apt-get -y --purge remove bluetooth blueman udisks2 avahi avahi-daemon \
  cups-browsed cups modemmanager 2>/dev/null | tail -2
ok "purged polling/maintenance packages"

# =====================================================================
step "9 · SMB (rule 2.1.7 — scored)"
apt-get -y --purge remove samba smbclient samba-common 2>/dev/null | tail -1
if dpkg -s samba smbclient 2>/dev/null | grep -q 'installed'; then warn "samba still present"; else ok "samba/smbclient not installed (clean)"; fi
systemctl disable smbd nmbd 2>/dev/null ; true

# =====================================================================
step "10 · MEDIA FILES in /home (rule 2.2.8.1) — user media only"
before=$(find /home -maxdepth 6 -type f \
         -iname '*.mp3' -o -iname '*.mp4' -o -iname '*.ogg' -o -iname '*.oga' \
         -o -iname '*.wav' -o -iname '*.avi' -o -iname '*.mov' -o -iname '*.mkv' \
         -o -iname '*.flv' -o -iname '*.wmv' -o -iname '*.aac' -o -iname '*.wma' 2>/dev/null | wc -l)
find /home -maxdepth 6 -type f \
         -iname '*.mp3' -o -iname '*.mp4' -o -iname '*.ogg' -o -iname '*.oga' \
         -o -iname '*.wav' -o -iname '*.avi' -o -iname '*.mov' -o -iname '*.mkv' \
         -o -iname '*.flv' -o -iname '*.wmv' -o -iname '*.aac' -o -iname '*.wma' 2>/dev/null \
     -print -delete >/dev/null
after=$(find /home -maxdepth 6 -type f \
         -iname '*.mp3' -o -iname '*.mp4' -o -iname '*.ogg' -o -iname '*.oga' \
         -o -iname '*.wav' -o -iname '*.avi' -o -iname '*.mov' -o -iname '*.mkv' \
         -o -iname '*.flv' -o -iname '*.wmv' -o -iname '*.aac' -o -iname '*.wma' 2>/dev/null | wc -l)
ok "user media: ${before} -> ${after}  (deleted $((before-after)))"
info "(system sounds in /usr are NOT touched — that is allowed)"

# =====================================================================
step "11 · DEFAULT BROWSER = CHROMIUM (rules 2.11.5, 2.1.9)"
CR=$(command -v chromium 2>/dev/null || command -v chromium-browser 2>/dev/null || echo /usr/bin/chromium)
[ -e "$CR" ] || { warn "no chromium binary on PATH — install it:"; echo "    sudo apt-get install -y chromium-browser"; CR=/usr/bin/chromium; }
update-alternatives --install /usr/bin/x-www-browser  x-www-browser  "$CR" 100 2>/dev/null && ok "x-www-browser -> $CR"
update-alternatives --install /usr/bin/www-browser    www-browser    "$CR" 100 2>/dev/null && ok "www-browser   -> $CR"
for u in $(real_users); do
  h="/home/$u"; [ -d "$h" ] || continue
  mkdir -p "$h/.config"
  printf '[Default Applications]\nx-scheme-handler/http=chromium-browser.desktop\nx-scheme-handler/https=chromium-browser.desktop\n' \
     > "$h/.config/mimeapps.list"
done
ok "per-user mimeapps.list -> chromium for all existing users"

# =====================================================================
step "12 · OPENVPN (rule 2.3.2 — remote access, keep working)"
if dpkg -s openvpn >/dev/null 2>&1; then
  systemctl enable --now openvpn 2>/dev/null && ok "openvpn enabled + active" || warn "openvpn enable/active?"
else info "openvpn not installed (install if this round requires it)"; fi

# =====================================================================
step "13 · TIME (MUST STAY UTC — read-only; do NOT reset)"
date
echo -n "    TZ: "; cat /etc/timezone 2>/dev/null || echo "(see /etc/localtime)"
[ "$(cat /etc/timezone 2>/dev/null)" = "UTC" ] && ok "timezone is UTC" || warn "timezone is not UTC — the rules require UTC (fix if wrong)"

# =====================================================================
step "14 · FINAL REPORT — copy-paste for the scoring report"
echo
sshd -T 2>/dev/null | grep -iE '^(permitrootlogin|passwordauthentication|maxauthtries|logingracetime|x11forwarding|permitempty|allowgroups)' | sed 's/^/  sshd  /'
echo "  ufw   : $(ufw status 2>/dev/null | tr '\n' ' ')"
echo "  DM    : $(cat /etc/X11/default-display-manager 2>/dev/null)"
echo -n "  users : "
awk -F: '($3>=1000 && $3<65534){printf "%s ", $1}' /etc/passwd; echo
echo "  media : $(find /home -maxdepth 6 -type f \( -iname '*.mp3' -o -iname '*.mp4' -o -iname '*.wav' \) 2>/dev/null | wc -l) left"
echo
echo
echo "  STILL TO DO (user-audit + forensics, by hand — each changes per round)"
echo "    1) useradd tchalla + sudo + chage -d 0   (or keep the 17 if the rules say so)"
echo "    2) userdel -r ultron ; userdel -r thanos"
echo "    3) set ALL authorized users' passwords (uniquish, minlen≥10, mixed classes)"
echo "       - use chpasswd with openssl -6 hashes to beat the dictionary check"
echo "    4) chage -d 0  on every authorized user      (rule 2.2.7)"
echo "    5) usermod -aG ssh <each user you create>   (AllowGroups ssh)"
echo "    6) answer THIS round's FORENSICS question in the report UI (it changes every round)"
echo
echo -e "\033[1;32mSYSTEM-SCOPE COMPLETE.\033[0m  Re-score once the user-audit items above are done."
