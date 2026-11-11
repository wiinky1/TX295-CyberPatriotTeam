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
            # This check now correctly preserves the 'team' user, 'root', and the user who ran the script.
            if [[ "$user" != "team" && "$user" != "root" && "$user" != "$SUDO_USER" ]]; then
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

# Find and remove unwanted media files
echo "Searching for MP3 and MP4 files..."
find / -type f \( -iname "*.mp3" -o -iname "*.mp4" \) 2>/dev/null > found_media.txt
echo "Found files logged in: $(pwd)/found_media.txt"

echo "Deleting found media files..."
find / -type f \( -iname "*.mp3" -o -iname "*.mp4" \) -delete 2>/dev/null

# Remove specific hacking/cracking tools
echo "Removing hacking tools..."
sudo apt-get remove --purge -y ophcrack aircrack-ng wireshark wireshark-*

# Remove common pre-installed games and unnecessary graphical tools
echo "Removing pre-installed games..."
games=(
    gnome-games
    gnome-chess
    gnome-mahjongg
    gnome-mines
    gnome-sudoku
    gnome-klotski
    gnome-tetravex
    aisleriot
)

for game in "${games[@]}"; do
    if dpkg -s "$game" &>/dev/null; then
        echo "Removing game: $game"
        sudo apt-get remove --purge -y "$game"
    fi
done

# General system cleanup
echo "Running system updates and cleanup..."
sudo apt update
sudo apt upgrade -y
sudo apt autoremove -y

echo "--- Script execution complete. ---"