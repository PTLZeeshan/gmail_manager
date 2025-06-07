#!/bin/bash

GM_DIR="/root/gmail_manager"
VENV="$GM_DIR/gmail_env/bin/activate"

# Create run_gmail_manager.sh
cat <<EOF > $GM_DIR/run_gmail_manager.sh
#!/bin/bash
cd $GM_DIR
source $VENV
python3 gmail_manager.py
EOF

# Create run_email_scanner.sh
cat <<EOF > $GM_DIR/run_email_scanner.sh
#!/bin/bash
cd $GM_DIR
source $VENV
python3 email_scanner.py
EOF

chmod +x $GM_DIR/run_gmail_manager.sh $GM_DIR/run_email_scanner.sh

echo "Wrapper scripts created and made executable:"
ls -l $GM_DIR/run_gmail_manager.sh $GM_DIR/run_email_scanner.sh
