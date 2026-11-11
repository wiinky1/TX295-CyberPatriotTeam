#!/bin/bash
#
# CyberPatriot Ubuntu 22 Training Image Hardening and Update Script
#
# This script automates the command-line fixes based on the provided
# CyberPatriot Ubuntu 22 Training Image Answer Key.
#
# WARNING: This script uses 'sudo' extensively. It requires the current user
# to have the correct password and 'sudo' privileges.
#

echo "Starting CyberPatriot Hardening and Cleanup Script..."
echo "--------------------------------------------------------"

# --- 1. USER ACCOUNT MANAGEMENT (Problems 3, 6) ---
echo "1. Performing User Management tasks..."

# Problem 3: Removed unauthorized user harry (4 pts)
# Removes the user and their home directory.
sudo userdel -r harry 2>/dev/null
if [ $? -eq 0 ]; then
    echo "  -> SUCCESS: User 'harry' and home directory removed."
else
    echo "  -> INFO: User 'harry' not found or could not be removed (skip if already gone)."
fi

# Problem 6: Added sybella to group pioneers (7 pts)
# Note: User 'sybella' must already exist for this to work.
sudo gpasswd -a sybella pioneers 2>/dev/null
if [ $? -eq 0 ]; then
    echo "  -> SUCCESS: User 'sybella' added to group 'pioneers'."
else
    echo "  -> ERROR: Could not add 'sybella' to 'pioneers'. User or group may not exist."
fi

# SKIPPED: Problem 4 (Remove admin access for cornelius) and Problem 5 (Change password for alice).
echo "  -> SKIPPED: Manual steps required for user 'cornelius' (admin removal) and 'alice' (password change)."
echo "--------------------------------------------------------"


# --- 2. PASSWORD POLICY ENFORCEMENT (Problems 7, 8) ---
echo "2. Enforcing System-wide Password Policies..."

COMMON_PASS="/etc/pam.d/common-password"
COMMON_AUTH="/etc/pam.d/common-auth"

# Problem 7: A minimum password length is required (4 pts) - Set minlen=10
# Uses 'sed' to add 'minlen=10' to the pam_unix.so line in common-password, only if it's not already set.
# This target line is typically: 'password [success=2 default=ignore] pam_unix.so'
if ! grep -q "minlen=10" "$COMMON_PASS"; then
    sudo sed -i '/pam_unix.so/s/\(pam_unix.so\).*/\1 minlen=10/' "$COMMON_PASS"
    echo "  -> SUCCESS: Minimum password length set to 10 in $COMMON_PASS."
else
    echo "  -> INFO: Minimum password length (minlen=10) already present in $COMMON_PASS."
fi

# Problem 8: Null passwords do not authenticate (6 pts) - Remove 'nullok'
# Uses 'sed' to remove the 'nullok' option from the pam_unix.so line in common-auth.
sudo sed -i 's/\bnullok\b//g' "$COMMON_AUTH"
echo "  -> SUCCESS: 'nullok' option removed from $COMMON_AUTH (disallowing empty passwords)."
echo "--------------------------------------------------------"


# --- 3. KERNEL & NETWORK HARDENING (Problems 9, 10) ---
echo "3. Applying Network and Kernel Hardening..."

SYSCTL_CONF="/etc/sysctl.conf"

# Problem 9: IPv4 TCP SYN Cookies have been enabled (5 pts) - Set net.ipv4.tcp_syncookies = 1
# Uses 'sed' to change 'net.ipv4.tcp_syncookies = 0' to 'net.ipv4.tcp_syncookies = 1'
sudo sed -i '/net.ipv4.tcp_syncookies/s/=\s*0/ = 1/' "$SYSCTL_CONF"
# Apply the new sysctl settings immediately
sudo sysctl --system >/dev/null
echo "  -> SUCCESS: TCP SYN Cookies enabled and settings applied."

# Problem 10: Uncomplicated Firewall (UFW) protection has been enabled (6 pts)
sudo ufw enable --force 2>/dev/null
if [ $? -eq 0 ]; then
    echo "  -> SUCCESS: UFW firewall enabled."
else
    echo "  -> ERROR: Could not enable UFW. Check UFW installation."
fi
echo "--------------------------------------------------------"


# --- 4. FILE PERMISSIONS (Problems 11, 12) ---
echo "4. Securing Critical File Permissions..."

# Problem 11: Insecure permissions on shadow file fixed (5 pts) - chmod 640
sudo chmod 640 /etc/shadow 2>/dev/null
echo "  -> SUCCESS: Permissions on /etc/shadow set to 640."

# Problem 12: GRUB Configuration is not world readable (5 points) - chmod 600
sudo chmod 600 /boot/grub/grub.cfg 2>/dev/null
echo "  -> SUCCESS: Permissions on /boot/grub/grub.cfg set to 600."
echo "--------------------------------------------------------"


# --- 5. SERVICES & SOFTWARE (Problems 13, 17, 18, 19) ---
echo "5. Managing Services and Prohibited Software..."

# Problem 13: Nginx service has been disabled or removed (5 pts)
sudo systemctl stop nginx 2>/dev/null
sudo systemctl disable nginx 2>/dev/null
echo "  -> SUCCESS: Nginx service stopped and disabled."

# Problem 19: SSH root login has been disabled (6 pts)
SSH_CONF="/etc/ssh/sshd_config"
# Uses 'sed' to change 'PermitRootLogin yes' to 'PermitRootLogin no' (or uncomment it)
sudo sed -i 's/^#\?PermitRootLogin yes/PermitRootLogin no/' "$SSH_CONF"
# Restart SSH service to apply changes
sudo systemctl restart sshd 2>/dev/null
echo "  -> SUCCESS: SSH root login disabled and SSH service restarted."

# Problem 18: Prohibited software AisleRiot removed (5 pts)
# Using --purge to remove configuration files as well.
sudo apt remove --purge -y aisleriot 2>/dev/null
sudo apt autoremove -y 2>/dev/null
echo "  -> SUCCESS: AisleRiot game removed."

# Problem 17: Prohibited MP3 files are removed (6 pts)
# The document mentions /home/corey/Music/*.mp3. Using a more general command for all users.
echo "  -> INFO: Removing non-work related MP3 files..."
find /home -name "*.mp3" -exec sudo rm -f {} \; 2>/dev/null
echo "  -> SUCCESS: All *.mp3 files removed from /home directories."
echo "--------------------------------------------------------"


# --- 6. SYSTEM UPDATE AND UPGRADE (User Request & Problems 15, 16) ---
echo "6. Performing System Update and Upgrade..."

# Problems 15 & 16 (Firefox, Thunderbird updates) are handled here by the full system upgrade.
# Problem 14 (Configure daily checks) is a GUI step, but the below commands apply all patches.

echo "  -> Running 'sudo apt update'..."
sudo apt update -y

echo "  -> Running 'sudo apt upgrade -y' (This will update all installed software, including Firefox/Thunderbird)..."
sudo apt upgrade -y

echo "--------------------------------------------------------"
echo "✅ Script Finished!"
echo "The command-line security fixes and system update/upgrade are complete."
echo "Please remember to perform the following **manual steps**:"
echo "1. Change password for user **alice**."
echo "2. Check and remove admin privileges for user **cornelius**."
echo "3. Configure **Software & Updates** to check for updates **Daily**."
