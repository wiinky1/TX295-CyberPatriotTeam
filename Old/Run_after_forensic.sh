#!/bin/bash

#Password policy 

update_login_defs() {
    local PARAM=$1
    local VALUE=$2
    local FILE="/etc/login.defs"

    # The sed command uses:
    # -i for in-place editing
    # -r for extended regex (cleaner patterns)
    # The pattern /^#?${PARAM}[[:space:]]/ searches for the parameter at the start of the line, 
    # optionally preceded by a '#' (if commented), and followed by whitespace.
    # The action c\\ replaces the entire line with the new, uncommented parameter and value.
    sudo sed -i -r "/^#?${PARAM}[[:space:]]/c\\${PARAM} ${VALUE}" "$FILE"
    echo "    Updated $PARAM to $VALUE"
}

update_login_defs "PASS_MAX_DAYS" "90"

update_login_defs "PASS_MIN_DAYS" "10"

update_login_defs "PASS_WARN_AGE" "14"

#Configuring fire wall

ufw --force reset

ufw default deny incoming

ufw default allow outgoing

ufw enable

#Shuting down APACHE2

systemctl stop apache2

sudo systemctl disable apache2

#Removing prohibated software

sudo apt-get purge ophcrack   

sudo apt-get remove --auto-remove ophcrack   

sudo apt-get remove --purge wireshark

apt purge aisleriot

#Disabling SSH root login

CONFIG_FILE="/etc/ssh/sshd_config"
SEARCH_PATTERN="^#?PermitRootLogin"
REPLACE_LINE="PermitRootLogin no"
SERVICE_NAME="ssh"


disable_root_login() {
    echo "🔍 Checking for existing '$REPLACE_LINE' in $CONFIG_FILE..."

    if sed -i "s/$SEARCH_PATTERN.*/$REPLACE_LINE/" "$CONFIG_FILE"; then
        echo "✅ Successfully set '$REPLACE_LINE' in $CONFIG_FILE."
    else
        echo "❌ Error: Failed to modify the configuration file. Ensure the file exists and you have write permissions."
        exit 1
    fi
}

restart_service() {
    echo "🔄 Restarting the SSH service ($SERVICE_NAME) to apply changes..."
    if systemctl restart "$SERVICE_NAME"; then
        echo "✅ SSH service restarted successfully."
        echo "🔒 Direct root login via SSH is now disabled."
    else
        echo "❌ Error: Failed to restart the SSH service. Please check the service status manually."
        exit 1
    fi
}

disable_root_login
restart_service

exit 0

#Deleting .mp3 and .mp4 files

sudo find / -type f -name "*.mp3" -delete 2>/dev/null
sudo find / -type f -name "*.mp4" -delete 2>/dev/null