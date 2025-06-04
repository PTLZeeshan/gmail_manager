from flask import Flask, render_template, request, redirect, url_for, flash, send_file
import os
import subprocess

app = Flask(__name__)
app.secret_key = 'your-very-secret-key'

GMAIL_MANAGER_DIR = os.path.expanduser('~/gmail_manager')
ACCOUNTS_FILE = os.path.join(GMAIL_MANAGER_DIR, 'accounts.txt')
SCAN_SENDERS_FILE = os.path.join(GMAIL_MANAGER_DIR, 'scan_senders.txt')
EXCEPTION_FILE = os.path.join(GMAIL_MANAGER_DIR, 'exception_do_not_delete.txt')
LOG_FILE = os.path.join(GMAIL_MANAGER_DIR, 'gmail_manager.log')
EMAIL_SCAN_LOG_FILE = os.path.join(GMAIL_MANAGER_DIR, 'email_scan.log')

def load_list(filename):
    if not os.path.exists(filename):
        return []
    with open(filename) as f:
        return [line.strip() for line in f if line.strip()]

def save_list(filename, items):
    with open(filename, 'w') as f:
        for item in items:
            f.write(item.strip() + '\n')

@app.route('/')
def dashboard():
    accounts = load_list(ACCOUNTS_FILE)
    return render_template('dashboard.html', accounts=accounts)

@app.route('/accounts', methods=['GET', 'POST'])
def accounts():
    accounts = load_list(ACCOUNTS_FILE)
    if request.method == 'POST':
        new_account = request.form['new_account'].strip()
        if new_account:
            os.makedirs(new_account, exist_ok=True)
            accounts.append(new_account)
            save_list(ACCOUNTS_FILE, accounts)
            flash('Account added.')
    return render_template('accounts.html', accounts=accounts)

@app.route('/accounts/<int:acc_index>/upload', methods=['POST'])
def upload_credentials(acc_index):
    if 'credentials' not in request.files:
        flash('No file uploaded')
        return redirect(url_for('accounts'))
    file = request.files['credentials']
    acc_dir = os.path.join(GMAIL_MANAGER_DIR, account)
    os.makedirs(acc_dir, exist_ok=True)
    file.save(os.path.join(acc_dir, 'credentials.json'))
    flash('credentials.json uploaded.')
    return redirect(url_for('accounts'))

@app.route('/keywords', methods=['GET', 'POST'])
def keywords():
    keywords = load_list(SCAN_SENDERS_FILE)
    if request.method == 'POST':
        if 'add' in request.form:
            k = request.form['keyword'].strip()
            if k:
                keywords.append(k)
        elif 'delete' in request.form:
            to_del = request.form.getlist('del')
            keywords = [k for k in keywords if k not in to_del]
        save_list(SCAN_SENDERS_FILE, keywords)
    return render_template('keywords.html', keywords=keywords)

@app.route('/exceptions', methods=['GET', 'POST'])
def exceptions():
    exceptions = load_list(EXCEPTION_FILE)
    if request.method == 'POST':
        if 'add' in request.form:
            e = request.form['exception'].strip()
            if e:
                exceptions.append(e)
        elif 'delete' in request.form:
            to_del = request.form.getlist('del')
            exceptions = [e for e in exceptions if e not in to_del]
        save_list(EXCEPTION_FILE, exceptions)
    return render_template('exceptions.html', exceptions=exceptions)

@app.route('/run/<script>')
def run_script(script):
    # This assumes run_gmail_manager.sh and run_email_scanner.sh are in GMAIL_MANAGER_DIR
    if script == 'gmail_manager':
        subprocess.Popen(['bash', os.path.join(GMAIL_MANAGER_DIR, 'run_gmail_manager.sh')])
        flash('Gmail Manager script triggered.')
    elif script == 'email_scanner':
        subprocess.Popen(['bash', os.path.join(GMAIL_MANAGER_DIR, 'run_email_scanner.sh')])
        flash('Email Scanner script triggered.')
    return redirect(url_for('dashboard'))

@app.route('/logs/<logfile>')
def logs(logfile):
    if logfile == 'manager':
        log_path = LOG_FILE
    elif logfile == 'scanner':
        log_path = EMAIL_SCAN_LOG_FILE
    else:
        return "Invalid log"
    with open(log_path) as f:
        content = f.read()
    return render_template('logs.html', log=content, logtype=logfile)

@app.route('/download/<logfile>')
def download_log(logfile):
    if logfile == 'manager':
        log_path = LOG_FILE
    elif logfile == 'scanner':
        log_path = EMAIL_SCAN_LOG_FILE
    else:
        return "Invalid log"
    return send_file(log_path, as_attachment=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8181, debug=True)
