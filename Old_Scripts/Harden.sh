#!/bin/bash

#---------------------------------------------
# CYBERPATRIOT HARDENING SCRIPT
# For Ubuntu-based images
#
# Usage:
#   1. Save this file as 'harden.sh'
#   2. Make it executable: chmod +x harden.sh
#   3. Run with root privileges: sudo ./harden.sh
#---------------------------------------------

# Check for root privileges
if [[ $EUID -ne 0 ]]; then
   echo "ERROR: This script must be run as root."
   exit 1
fi

echo "--- Starting CyberPatriot Hardening Script ---"

# --- User and Group Management ---
echo "--> Hardening user accounts..."

# Bad users to remove. Add more as you find them.
for user in bill jenna guest student; do
    if id "$user" &>/dev/null; then
        echo "Removing user: $user"
        userdel -r "$user"
    fi
done

# Remove unnecessary users from the 'sudo' group
for group in sudo; do
    if getent group "$group" &>/dev/null; then
        echo "Checking '$group' group..."
        for user in $(getent group "$group" | cut -d: -f4 | sed 's/,/ /g'); do
            # The following line is the modification.
            # It checks that the user is NOT 'team', 'root', or the current user.
            if [[ "$user" != "team" && "$user" != "root" && "$user" != "$(whoami)" ]]; then
                echo "Removing user '$user' from group '$group'."
                gpasswd -d "$user" "$group"
            fi
        done
    fi
done

# --- File Permissions and System Hardening ---
echo "--> Fixing file permissions..."
echo "Searching for world-writable files and directories..."
find / -type f -perm -o+w -exec chmod o-w {} \; 2>/dev/null
find / -type d -perm -o+w -exec chmod o-w {} \; 2>/dev/null

echo "Securing critical system files..."
chmod 640 /etc/passwd /etc/group /etc/shadow
chmod 600 /etc/sudoers /etc/gshadow

# --- Service and Network Hardening ---
echo "--> Hardening network and services..."

services=(
    telnet.socket
    ftp.service
    nfs-server.service
    rsh.socket
    vsftpd.service
)

for service in "${services[@]}"; do
    if systemctl is-active --quiet "$service"; then
        echo "Disabling and stopping active service: $service"
        systemctl stop "$service"
        systemctl disable "$service"
    fi
done

# Enable and configure UFW (Uncomplicated Firewall)
echo "Configuring firewall with UFW..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw enable

# --- Final Touches ---
echo "--> Cleaning up..."
sudo apt update
sudo apt upgrade
sudo apt autoremove

echo "--- Script execution complete. ---"