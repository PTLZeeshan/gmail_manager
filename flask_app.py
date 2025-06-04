import os
import pickle
import subprocess
from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from google_auth_oauthlib.flow import Flow

app = Flask(__name__)
app.secret_key = 'your-very-secret-key'

GMAIL_MANAGER_DIR = os.path.expanduser('~/gmail_manager')
ACCOUNTS_FILE = os.path.join(GMAIL_MANAGER_DIR, 'accounts.txt')
LOG_FILE = os.path.join(GMAIL_MANAGER_DIR, 'gmail_manager.log')
EMAIL_SCAN_LOG_FILE = os.path.join(GMAIL_MANAGER_DIR, 'email_scan.log')

def load_account_list():
    if not os.path.exists(ACCOUNTS_FILE):
        return []
    with open(ACCOUNTS_FILE) as f:
        return [line.strip() for line in f if line.strip()]

def save_account_list(accounts):
    with open(ACCOUNTS_FILE, 'w') as f:
        for acc in accounts:
            f.write(acc.strip() + '\n')

def account_path(acc_index):
    accounts = load_account_list()
    if acc_index < 0 or acc_index >= len(accounts):
        return None
    return accounts[acc_index]

def load_list(filename):
    if not os.path.exists(filename):
        return []
    with open(filename) as f:
        return [line.strip() for line in f if line.strip()]

def save_list(filename, items):
    with open(filename, 'w') as f:
        for item in items:
            f.write(item.strip() + '\n')

def ensure_account_files(account_dir):
    os.makedirs(account_dir, exist_ok=True)
    for fname in ["scan_senders.txt", "exception_do_not_delete.txt"]:
        path = os.path.join(account_dir, fname)
        if not os.path.exists(path):
            with open(path, 'w') as f:
                pass

@app.route('/')
def dashboard():
    accounts = load_account_list()
    return render_template('dashboard.html', accounts=accounts)

@app.route('/accounts', methods=['GET', 'POST'])
def accounts():
    accounts = load_account_list()
    if request.method == 'POST':
        new_account = request.form['new_account'].strip()
        if new_account and new_account not in accounts:
            os.makedirs(new_account, exist_ok=True)
            accounts.append(new_account)
            save_account_list(accounts)
            ensure_account_files(new_account)
            flash('Account added.')
        else:
            flash('Account path is empty or already exists.')
    return render_template('accounts.html', accounts=accounts)

@app.route('/accounts/<int:acc_index>/upload', methods=['POST'])
def upload_credentials(acc_index):
    accounts = load_account_list()
    if acc_index < 0 or acc_index >= len(accounts):
        flash('Invalid account index.')
        return redirect(url_for('accounts'))
    if 'credentials' not in request.files:
        flash('No file uploaded')
        return redirect(url_for('accounts'))
    file = request.files['credentials']
    acc_dir = accounts[acc_index]
    os.makedirs(acc_dir, exist_ok=True)
    file.save(os.path.join(acc_dir, 'credentials.json'))
    flash(f'credentials.json uploaded for {acc_dir}.')
    return redirect(url_for('accounts'))

@app.route('/accounts/<int:acc_index>/oauth')
def start_auth(acc_index):
    account_dir = account_path(acc_index)
    if not account_dir:
        flash('Invalid account.')
        return redirect(url_for('accounts'))
    credentials_path = os.path.join(account_dir, 'credentials.json')
    if not os.path.exists(credentials_path):
        flash('credentials.json missing for this account.')
        return redirect(url_for('accounts'))
    flow = Flow.from_client_secrets_file(
        credentials_path,
        scopes=['https://mail.google.com/'],
        redirect_uri='urn:ietf:wg:oauth:2.0:oob'
    )
    auth_url, _ = flow.authorization_url(prompt='consent')
    return render_template('auth.html', auth_url=auth_url, acc_index=acc_index, account_dir=account_dir)

@app.route('/accounts/<int:acc_index>/oauth', methods=['POST'])
def finish_auth(acc_index):
    account_dir = account_path(acc_index)
    if not account_dir:
        flash('Invalid account.')
        return redirect(url_for('accounts'))
    code = request.form['auth_code'].strip()
    credentials_path = os.path.join(account_dir, 'credentials.json')
    token_path = os.path.join(account_dir, 'token.pickle')
    flow = Flow.from_client_secrets_file(
        credentials_path,
        scopes=['https://mail.google.com/'],
        redirect_uri='urn:ietf:wg:oauth:2.0:oob'
    )
    try:
        flow.fetch_token(code=code)
        creds = flow.credentials
        with open(token_path, 'wb') as token:
            pickle.dump(creds, token)
        flash('Account authenticated successfully!')
    except Exception as e:
        flash('Authentication failed: ' + str(e))
    return redirect(url_for('accounts'))

@app.route('/accounts/<int:acc_index>/keywords', methods=['GET', 'POST'])
def keywords(acc_index):
    account_dir = account_path(acc_index)
    if not account_dir:
        flash('Invalid account.')
        return redirect(url_for('accounts'))
    ensure_account_files(account_dir)
    scan_file = os.path.join(account_dir, 'scan_senders.txt')
    keywords = load_list(scan_file)
    if request.method == 'POST':
        if 'add' in request.form:
            k = request.form['keyword'].strip()
            if k and k not in keywords:
                keywords.append(k)
        elif 'delete' in request.form:
            to_del = request.form.getlist('del')
            keywords = [k for k in keywords if k not in to_del]
        save_list(scan_file, keywords)
    accounts = load_account_list()
    return render_template('keywords.html', keywords=keywords, acc_index=acc_index, accounts=accounts, account_dir=account_dir)

@app.route('/accounts/<int:acc_index>/exceptions', methods=['GET', 'POST'])
def exceptions(acc_index):
    account_dir = account_path(acc_index)
    if not account_dir:
        flash('Invalid account.')
        return redirect(url_for('accounts'))
    ensure_account_files(account_dir)
    ex_file = os.path.join(account_dir, 'exception_do_not_delete.txt')
    exceptions = load_list(ex_file)
    if request.method == 'POST':
        if 'add' in request.form:
            e = request.form['exception'].strip()
            if e and e not in exceptions:
                exceptions.append(e)
        elif 'delete' in request.form:
            to_del = request.form.getlist('del')
            exceptions = [e for e in exceptions if e not in to_del]
        save_list(ex_file, exceptions)
    accounts = load_account_list()
    return render_template('exceptions.html', exceptions=exceptions, acc_index=acc_index, accounts=accounts, account_dir=account_dir)

@app.route('/run/<script>')
def run_script(script):
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
    if not os.path.exists(log_path):
        content = "(No log file found)"
    else:
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
