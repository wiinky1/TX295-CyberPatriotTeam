#!/bin/bash

echo "--- Starting CyberPatriot Hardening Script ---"


# --- File Permissions and System Hardening ---
echo "--> Fixing file permissions..."
echo "Searching for world-writable files and directories..."
find / -type f -perm -o+w -exec chmod o-w {} \; 2>/dev/null
find / -type d -perm -o+w -exec chmod o-w {} \; 2>/dev/null

#echo "Securing critical system files..."
#chmod 640 /etc/passwd /etc/group /etc/shadow
#chmod 600 /etc/sudoers /etc/gshadow

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

sudo apt-get purge ophcrack   
sudo apt-get remove --auto-remove ophcrack   
sudo apt-get remove --purge wireshark

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