#!/bin/bash

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
