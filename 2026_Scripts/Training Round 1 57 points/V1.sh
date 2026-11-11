#!/usr/bin/env bash

#updating
sudo apt update

sudo apt upgrade -y

echo "##################################################################################################"
echo "UPDATED"
echo "##################################################################################################"


#configuring root password
sudo getent shadow root

sudo passwd -l root

sudo getent shadow root

echo "##################################################################################################"
echo "Root password nolonger blank"
echo "##################################################################################################"

#min password length
sudo apt update
sudo apt install -y libpam-pwquality

# Set minimum password length to 12
sudo sed -i '/pam_unix\.so/ s/$/ minlen=12/' /etc/pam.d/common-password

echo "##################################################################################################"
echo "Min password length set"
echo "##################################################################################################"


#configuring account lockout policy
sudo tee /usr/share/pam-configs/faillock > /dev/null << 'EOF'
Name: Lockout on failed logins
Default: no
Priority: 0
Auth-Type: Primary
Auth:
	[default=die] pam_faillock.so authfail
EOF

sudo tee /usr/share/pam-configs/faillock_reset > /dev/null << 'EOF'
Name: Reset lockout on success
Default: no
Priority: 0
Auth-Type: Additional
Auth:
	required pam_faillock.so authsucc
EOF

sudo tee /usr/share/pam-configs/faillock_notify > /dev/null << 'EOF'
Name: Notify on account lockout
Default: no
Priority: 1024
Auth-Type: Primary
Auth:
	requisite pam_faillock.so preauth
EOF

sudo pam-auth-update --enable faillock faillock_reset faillock_notify

echo "####################################################################################################"
echo "Account lockout policy configured"
echo "####################################################################################################"


#disallowing null passwords
sudo sed -i '/pam_unix\.so/ s/nullok//g' /etc/pam.d/common-auth

echo "####################################################################################################"
echo "Null passwords disabled"
echo "####################################################################################################"

# Enable IPv4 TCP SYN Cookies
if grep -q "^net.ipv4.tcp_syncookies" /etc/sysctl.conf; then
    sudo sed -i 's/^net.ipv4.tcp_syncookies.*/net.ipv4.tcp_syncookies=1/' /etc/sysctl.conf
else
    echo "net.ipv4.tcp_syncookies=1" | sudo tee -a /etc/sysctl.conf
fi

sudo sysctl --system

echo "################################################################################"
echo "IPv4 TCP SYN cookies enabled"
echo "################################################################################"

# Enable Uncomplicated Firewall (UFW)
sudo ufw enable

echo "################################################################################"
echo "UFW protection enabled"
echo "################################################################################"

# Disable and stop Nginx service
sudo systemctl disable --now nginx

echo "################################################################################"
echo "Nginx service disabled"
echo "################################################################################"

# Disable and stop Squid proxy service
sudo systemctl disable --now squid

echo "################################################################################"
echo "Squid service disabled"
echo "################################################################################"

# Update package lists and upgrade vsftpd specifically
sudo apt update
sudo apt-get --only-upgrade install -y vsftpd

echo "################################################################################"
echo "Vsftpd updated"
echo "################################################################################"

# Find and remove prohibited OGG media files across user directories
sudo find /home -type f -name "*.ogg" -delete

echo "################################################################################"
echo "Prohibited OGG files removed"
echo "################################################################################"

# Find and remove prohibited software archive pyrdp
sudo find / -name "*pyrdp*.zip" -exec rm -f {} +

echo "################################################################################"
echo "Prohibited software archive pyrdp removed"
echo "################################################################################"

# Purge unauthorized software packages (doona, xprobe)
sudo apt purge -y doona xprobe

echo "################################################################################"
echo "Unauthorized software removed"
echo "################################################################################"

# Stop and remove the zod backdoor
sudo pkill -f kneelB4zod.py
sudo rm -f /usr/share/zod/kneelB4zod.py

echo "################################################################################"
echo "Zod backdoor removed"
echo "################################################################################"