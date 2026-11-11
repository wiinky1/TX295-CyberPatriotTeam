#!/usr/bin/env bash
# cyberpatriot_user_manager.sh
# Safe user/group management script for CyberPatriot Linux Mint systems.
# ------------------------------------------------------------
# Usage:
#   sudo ./cyberpatriot_user_manager.sh admins.txt allowed.txt [--apply]
#
# Default = dry-run. Use --apply to actually modify users.
# ------------------------------------------------------------

set -euo pipefail

APPLY=false
MIN_HUMAN_UID=1000
SUDO_GROUP="sudo"
NORMAL_GROUP="users"   # Standard desktop user group in Mint

# --- Parse arguments ---
if [[ $# -lt 2 ]]; then
  echo "Usage: sudo $0 <admins_list> <allowed_users_list> [--apply]"
  exit 1
fi

ADMINS_FILE="$1"
ALLOWED_FILE="$2"

if [[ "${3:-}" == "--apply" ]]; then
  APPLY=true
  echo "⚠️ APPLY MODE: changes WILL be made."
else
  echo "🧪 DRY-RUN MODE: no changes will be made. Use --apply to apply."
fi

if [[ ! -f "$ADMINS_FILE" ]] || [[ ! -f "$ALLOWED_FILE" ]]; then
  echo "Error: both admin and allowed user files must exist."
  exit 1
fi

# --- Extract usernames (ignore passwords, labels, etc.) ---
extract_usernames() {
  grep -Eo '^[[:alnum:]_.-]+' "$1" | sort -u
}

mapfile -t ADMINS < <(extract_usernames "$ADMINS_FILE")
mapfile -t ALLOWED < <(extract_usernames "$ALLOWED_FILE")

echo "✅ Admin list:"
printf "  %s\n" "${ADMINS[@]}"
echo "✅ Allowed (standard) user list:"
printf "  %s\n" "${ALLOWED[@]}"

# --- Protect current user ---
CURRENT_USER="${SUDO_USER:-$(whoami)}"
if [[ ! " ${ADMINS[*]} " =~ " ${CURRENT_USER} " ]]; then
  echo "⚠️ Adding current user '$CURRENT_USER' to admin list to prevent lockout."
  ADMINS+=("$CURRENT_USER")
fi

# --- Ensure groups exist ---
for grp in "$SUDO_GROUP" "$NORMAL_GROUP"; do
  if ! getent group "$grp" >/dev/null; then
    echo "⚠️ Group '$grp' missing — creating it."
    $APPLY && groupadd "$grp"
  fi
done

# --- Function to safely ensure a user exists ---
ensure_user_exists() {
  local user="$1"
  if id "$user" &>/dev/null; then
    echo "👤 User '$user' exists."
  else
    echo "➕ Creating user '$user'..."
    $APPLY && useradd -m -s /bin/bash "$user"
  fi
}

# --- Function to ensure user is in group ---
ensure_in_group() {
  local user="$1"
  local group="$2"
  if id -nG "$user" | grep -qw "$group"; then
    echo "✔️ '$user' already in '$group'."
  else
    echo "➕ Adding '$user' to '$group'."
    $APPLY && usermod -aG "$group" "$user"
  fi
}

# --- Ensure all admins and allowed users exist and are grouped properly ---
echo "🔧 Configuring admins..."
for user in "${ADMINS[@]}"; do
  ensure_user_exists "$user"
  ensure_in_group "$user" "$SUDO_GROUP"
done

echo "🔧 Configuring standard users..."
for user in "${ALLOWED[@]}"; do
  ensure_user_exists "$user"
  ensure_in_group "$user" "$NORMAL_GROUP"
done

# --- Find all existing local human users ---
mapfile -t EXISTING_USERS < <(awk -F: -v minuid="$MIN_HUMAN_UID" '($3 >= minuid){print $1}' /etc/passwd)

# --- Determine removal list ---
TO_REMOVE=()
for u in "${EXISTING_USERS[@]}"; do
  if [[ "$u" == "root" || "$u" == "$CURRENT_USER" ]]; then
    continue
  fi
  if [[ ! " ${ADMINS[*]} " =~ " ${u} " && ! " ${ALLOWED[*]} " =~ " ${u} " ]]; then
    TO_REMOVE+=("$u")
  fi
done

# --- Show removal summary ---
if [[ ${#TO_REMOVE[@]} -gt 0 ]]; then
  echo "🗑️ Users not authorized (candidates for removal):"
  printf "  %s\n" "${TO_REMOVE[@]}"
  if $APPLY; then
    for u in "${TO_REMOVE[@]}"; do
      echo "❌ Removing user '$u'..."
      userdel -r "$u" || echo "⚠️ Failed to delete '$u' (check manually)"
    done
  else
    echo "Dry-run: would remove users above."
  fi
else
  echo "✅ No unauthorized users found."
fi

echo
echo "🏁 Script complete. $($APPLY && echo 'Changes applied.' || echo 'Dry-run only, no changes made.')"
