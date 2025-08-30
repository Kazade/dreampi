#!/bin/bash

# BBA Mode tool written by scrivanidc@gmail.com - jun/2023
# --------------------------------------------------------
# We are living our best Dreamcast Lives
# --------------------------------------------------------

echo "Stardard DreamPi Service - Stopping ..."
sudo pgrep -f tcpdump | sudo xargs kill -9 2>/dev/null
sudo pgrep -f python | sudo xargs kill -9 2>/dev/null
#Just to make sure
sudo killall -q tcpdump 2>/dev/null
sudo killall -q python2.7 2>/dev/null
sudo service dreampi stop
echo "Stardard DreamPi Service - Stopped"
echo "------------------------------------------------------------"

if [ "$1" == 0 ]; then
    exit 0
fi

d=$(grep -m 1 "eth=" "$2" 2>/dev/null | cut -d '"' -f 2)
py="$3"

if [ "$1" == 2 ] || [ -z "$1" ]; then
echo "Manual List Autonomous Dreamcast Now Service - Starting ..."
echo ""
echo " 0 - Browsing/Blank Session"
echo " 1 - Phantasy Star Online"
echo " 2 - Quake III Arena"
echo " 3 - 4x4 Evolution"
echo " 4 - Alien Front Online"
echo " 5 - ChuChu Rocket"
echo " 6 - Daytona USA"
echo " 7 - DeeDee Planet"
echo " 8 - Driving Strikers"
echo " 9 - Internet Game Pack"
echo "10 - Maximum Pool"
echo "11 - Mobile Suit Gundam: Federation vs. Zeon"
echo "12 - Monaco Grand Prix Online"
echo "13 - Next Tetris, The"
echo "14 - Ooga Booga"
echo "15 - PBA Bowling"
echo "16 - POD Speedzone"
echo "17 - Planet Ring"
echo "18 - Starlancer"
echo "19 - Toy Racer"
echo "20 - Worms World Party"
echo "21 - 2K Series: NBA 2K1"
echo "22 - 2K Series: NBA 2K2"
echo "23 - 2K Series: NCAA 2K2"
echo "24 - 2K Series: NFL 2K1"
echo "25 - 2K Series: NFL 2K2"
echo "26 - Reboot and restart standard DreamPi (modem)"
echo ""
echo "Choose game number > "
    read n
elif [ "$1" == 1 ]; then
  n=0
fi

if [ -z "$2" ]; then d="eth0"; fi
if [ -z "$3" ]; then py="/home/pi/dreampi/bba_bin.py"; fi

chk='^[0-9]+$'
if ! [[ $n =~ $chk ]]; then
  echo "Not a number"
  exit 0
fi

if [[ $n -gt 26 ]]; then
  echo "Invalid option"
elif [[ $n -eq 26 ]]; then
  sudo reboot
else
  echo ""
  sudo python2.7 "$py" "$n" "$d" --no-daemon &
  sleep 6
  echo ""
  echo "Running in background"
  echo "------------------------------------------------------------"
fi
exit 0
