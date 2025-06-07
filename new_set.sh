#!/bin/bash

set -e

# ======== CONFIG ========
GITHUB_REPO="https://github.com/YOUR_USERNAME/YOUR_REPO.git"
PROJECT_DIR="$HOME/gmail_manager"
ACCOUNTS=("account1" "account2" "account3")
PYTHON_VERSION=python3
FLASK_PORT=8181

remove_gmail_manager() {
    rm -rf "$PROJECT_DIR"
    sudo systemctl stop gmail_manager.timer || true
    sudo systemctl disable gmail_manager.timer || true
    sudo systemctl stop email_scanner.timer || true
    sudo systemctl disable email_scanner.timer || true
    sudo systemctl stop flask_app.service || true
    sudo systemctl disable flask_app.service || true
    sudo rm -f /etc/systemd/system/gmail_manager.{service,timer}
    sudo rm -f /etc/systemd/system/email_scanner.{service,timer}
    sudo rm -f /etc/systemd/system/flask_app.service
    sudo systemctl daemon-reload
}

read -p "Remove previous Gmail Manager setup (recommended on upgrade)? (Y/N): " run_before
if [[ $run_before =~ ^[Yy]$ ]]; then
    remove_gmail_manager
    echo "Previous setup removed."
fi

sudo apt update && sudo apt upgrade -y
sudo apt install -y $PYTHON_VERSION $PYTHON_VERSION-venv git

# ======== CLONE FROM GITHUB ========
if [ ! -d "$PROJECT_DIR" ]; then
    git clone "$GITHUB_REPO" "$PROJECT_DIR"
else
    cd "$PROJECT_DIR"
    git pull
fi

cd "$PROJECT_DIR"

# ======== PYTHON ENVIRONMENT ========
$PYTHON_VERSION -m venv gmail_env
source gmail_env/bin/activate

if [ -f requirements.txt ]; then
    pip install --upgrade pip
    pip install -r requirements.txt
else
    pip install --upgrade google-auth-oauthlib google-auth-httplib2 google-api-python-client python-dateutil email-validator google-auth flask
fi

# ======== ACCOUNT DIRECTORIES & accounts.txt ========
for account in "${ACCOUNTS[@]}"; do
    mkdir -p "$PROJECT_DIR/$account"
done

cat <<EOF > accounts.txt
$PROJECT_DIR/account1
$PROJECT_DIR/account2
$PROJECT_DIR/account3
EOF

# ======== CREATE BASIC FILES IN EACH ACCOUNT ========
for account in "${ACCOUNTS[@]}"; do
    cd "$PROJECT_DIR/$account"
    touch scan_senders.txt exception_do_not_delete.txt scanned_email_list.txt del_emails_record.txt already_emailed.txt draft_emails.txt reply_message.txt
    chmod 600 scan_senders.txt exception_do_not_delete.txt scanned_email_list.txt del_emails_record.txt already_emailed.txt draft_emails.txt reply_message.txt

    # Optionally populate scan_senders.txt with defaults
    if [ ! -s scan_senders.txt ]; then
        echo -e "keyword:offer\nkeyword:promotion\nkeyword:news\nkeyword:" > scan_senders.txt
    fi
done

cd "$PROJECT_DIR"

# ======== SYSTEMD SERVICES & TIMERS ========
read -p "Enter OnBootSec in minutes for gmail_manager (default 1): " on_boot_min
read -p "Enter OnUnitActiveSec in minutes for gmail_manager (default 10): " on_unit_active_min
on_boot_sec="${on_boot_min:-1}min"
on_unit_active_sec="${on_unit_active_min:-10}min"

cat <<EOF | sudo tee /etc/systemd/system/gmail_manager.service
[Unit]
Description=Gmail Manager Service
After=network.target

[Service]
ExecStart=/bin/bash $PROJECT_DIR/run_gmail_manager.sh
User=$(whoami)
Group=$(whoami)
WorkingDirectory=$PROJECT_DIR

[Install]
WantedBy=multi-user.target
EOF

cat <<EOF | sudo tee /etc/systemd/system/gmail_manager.timer
[Unit]
Description=Run Gmail Manager at scheduled intervals

[Timer]
OnBootSec=$on_boot_sec
OnUnitActiveSec=$on_unit_active_sec

[Install]
WantedBy=timers.target
EOF

cat <<EOF | sudo tee /etc/systemd/system/email_scanner.service
[Unit]
Description=Email Scanner Service
After=network.target

[Service]
ExecStart=/bin/bash $PROJECT_DIR/run_email_scanner.sh
User=$(whoami)
Group=$(whoami)
WorkingDirectory=$PROJECT_DIR

[Install]
WantedBy=multi-user.target
EOF

cat <<EOF | sudo tee /etc/systemd/system/email_scanner.timer
[Unit]
Description=Run Email Scanner every 10 minutes

[Timer]
OnBootSec=1min
OnUnitActiveSec=10min

[Install]
WantedBy=timers.target
EOF

# ======== FLASK SYSTEMD SERVICE ========
cat <<EOF | sudo tee /etc/systemd/system/flask_app.service
[Unit]
Description=Gmail Manager Flask Web UI
After=network.target

[Service]
Type=simple
User=$(whoami)
Group=$(whoami)
WorkingDirectory=$PROJECT_DIR
ExecStart=$PROJECT_DIR/gmail_env/bin/python3 $PROJECT_DIR/flask_app.py
Restart=always
Environment=PYTHONUNBUFFERED=1
[Install]
WantedBy=multi-user.target
EOF

sudo chmod 644 /etc/systemd/system/gmail_manager.{service,timer}
sudo chmod 644 /etc/systemd/system/email_scanner.{service,timer}
sudo chmod 644 /etc/systemd/system/flask_app.service
sudo systemctl daemon-reload
sudo systemctl enable gmail_manager.timer email_scanner.timer flask_app.service
sudo systemctl restart gmail_manager.timer email_scanner.timer flask_app.service

echo "Systemd timers/services enabled and started."
sudo systemctl status gmail_manager.timer --no-pager
sudo systemctl status email_scanner.timer --no-pager
sudo systemctl status flask_app.service --no-pager

echo "------------------------------------------"
echo "SETUP COMPLETE!"
echo "MANUAL STEPS STILL NEEDED:"
echo "1. Copy your Google credentials.json to each account directory:"
for account in "${ACCOUNTS[@]}"; do
    echo "   $PROJECT_DIR/$account/credentials.json"
done
echo "2. Run each script once for initial Google authentication:"
echo "   cd $PROJECT_DIR && source gmail_env/bin/activate"
echo "   ./run_gmail_manager.sh"
echo "   ./run_email_scanner.sh"
echo "3. Your Flask UI runs at: http://localhost:$FLASK_PORT/"
echo "------------------------------------------"
echo "Logs:"
echo "  $PROJECT_DIR/gmail_manager.log"
echo "  $PROJECT_DIR/email_scan.log"
