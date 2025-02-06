#!/bin/bash
GITHUB_REPO="https://github.com/byfranke/web-toolkit"
TEMP_DIR="$(mktemp -d)"

print_banner() {
echo
echo "___________________oo_____________oo____________________ooo___oo______oo___oo____"
echo "oo_______o__ooooo__oooooo_________oo_____ooooo___ooooo___oo___oo___o_______oo____"
echo "oo__oo___o_oo____o_oo___oo_______oooo___oo___oo_oo___oo__oo___oo__o___oo__oooo___"
echo "oo__oo___o_ooooooo_oo___oo_ooooo__oo____oo___oo_oo___oo__oo___oooo____oo___oo____"
echo "_oo_oo__o__oo______oo___oo________oo__o_oo___oo_oo___oo__oo___oo__o___oo___oo__o_"
echo "__oo__oo____ooooo__oooooo__________ooo___ooooo___ooooo__ooooo_oo___o_oooo___ooo__"
echo "_________________________________________________________________________________"
echo
echo "                              WEB-TOOLKIT byfranke"
echo "---------------------------------------------------------------------------------"
}

install_dependencies() {
echo "[*] Checking Python and pip..."
if ! command -v python3 &> /dev/null; then
  echo "[!] Python3 not found. Installing..."
  if command -v apt-get &> /dev/null; then
    sudo apt-get update && sudo apt-get install python3 -y
  elif command -v pacman &> /dev/null; then
    sudo pacman -Syu --noconfirm python
  else
    echo "[!] No apt-get or pacman found. Please install python3 manually."
  fi
else
  echo "[+] Python3 found."
fi
if ! command -v pip3 &> /dev/null; then
  echo "[!] pip3 not found. Installing..."
  if command -v apt-get &> /dev/null; then
    sudo apt-get install python3-pip -y
  elif command -v pacman &> /dev/null; then
    sudo pacman -S --noconfirm python-pip
  else
    echo "[!] No apt-get or pacman found. Please install pip3 manually."
  fi
else
  echo "[+] pip3 found."
fi
echo "[*] Installing required Python dependencies..."
if [ -f "requirements.txt" ]; then
  pip3 install -r requirements.txt
else
  echo "[!] requirements.txt not found. Skipping pip install."
fi
echo "[*] Checking additional system dependencies..."
for tool in nmap sqlmap wget curl gobuster; do
  if ! command -v "$tool" &> /dev/null; then
    echo "[!] $tool not found. Installing..."
    if command -v apt-get &> /dev/null; then
      sudo apt-get update && sudo apt-get install -y "$tool"
    elif command -v pacman &> /dev/null; then
      sudo pacman -Syu --noconfirm "$tool"
    else
      echo "[!] No apt-get or pacman found. Please install $tool manually."
    fi
  else
    echo "[+] $tool found."
  fi
done
echo "[*] Installing wordlists (seclists)..."
if command -v apt-get &> /dev/null; then
  sudo apt-get install -y seclists
elif command -v pacman &> /dev/null; then
  sudo pacman -Syu --noconfirm seclists
else
  echo "[!] No apt-get or pacman found. Please install seclists manually."
fi
echo "[+] All dependencies checked/installed."
}

install_local_version() {
echo "[*] Installing local version of Web-Toolkit..."
if [ ! -f "web-toolkit.py" ]; then
  echo "[!] web-toolkit.py not found in current directory."
  return
fi
install_dependencies
sudo chmod +x web-toolkit.py
sudo cp web-toolkit.py /usr/bin/web-toolkit
echo "[+] Web-Toolkit installed as /usr/bin/web-toolkit"
read -p "Do you want to run Web-Toolkit now? (y/n): " choice
if [[ $choice =~ ^[Yy]$ ]]; then
  web-toolkit
fi
}

check_and_update() {
echo "[*] Checking for the latest version on GitHub ($GITHUB_REPO)..."
git clone "$GITHUB_REPO" "$TEMP_DIR" 2>/dev/null
if [ $? -ne 0 ]; then
  echo "[!] Failed to clone repository. Check your internet connection or git installation."
  rm -rf "$TEMP_DIR"
  return
fi
BACKUP_DIR="Obsolete_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
echo "[*] Moving old files to $BACKUP_DIR..."
shopt -s extglob
find . -maxdepth 1 -type f ! -name "$(basename "$0")" ! -name "setup.sh" -exec mv {} "$BACKUP_DIR" \;
find . -maxdepth 1 -type d ! -name "$BACKUP_DIR" ! -name "." ! -name ".." -exec mv {} "$BACKUP_DIR" \;
mv "$TEMP_DIR"/* ./
rm -rf "$TEMP_DIR"
echo "[+] Updated to the latest version. Old files moved to '$BACKUP_DIR'."
}

show_menu() {
while true; do
  print_banner
  echo "Choose an option below:"
  echo
  echo "1) Install/Configure Local Version"
  echo "2) Check for Latest Version and Update"
  echo "3) Exit"
  echo
  read -p "Enter your choice: " choice
  case $choice in
    1)
      install_local_version
      ;;
    2)
      check_and_update
      ;;
    3)
      echo "Exiting..."
      exit 0
      ;;
    *)
      echo "[!] Invalid option. Please try again."
      ;;
  esac
  echo
  read -p "Press Enter to return to the menu..." dummy
done
}

show_menu
