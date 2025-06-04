#!/bin/bash

# Function to remove Gmail Manager setup and associated systemd services and timers
remove_gmail_manager() {
    local user_home=\$1
    rm -rf "${user_home}/gmail_manager"
    pip uninstall -y google-auth-oauthlib google-auth-httplib2 google-api-python-client python-dateutil email-validator

    # Remove systemd services and timers
    sudo systemctl stop gmail_manager.timer
    sudo systemctl disable gmail_manager.timer
    sudo systemctl stop email_scanner.timer
    sudo systemctl disable email_scanner.timer
    sudo rm -f /etc/systemd/system/gmail_manager.service
    sudo rm -f /etc/systemd/system/gmail_manager.timer
    sudo rm -f /etc/systemd/system/email_scanner.service
    sudo rm -f /etc/systemd/system/email_scanner.timer
    sudo systemctl daemon-reload
}

# Ask if user wants to run as root
read -p "Do you want to run this script as root? (Y/N): " run_as_root

if [[ $run_as_root =~ ^[Yy]$ ]]; then
    user_home="/root"
else
    user_home="/home/$(whoami)"
fi

# Ask if script has been run before
read -p "Have you run this script before? (Y/N): " run_before

if [[ $run_before =~ ^[Yy]$ ]]; then
    remove_gmail_manager "$user_home"
    echo "Previous Gmail Manager setup and systemd services have been removed."
fi

# Gmail Manager Setup Script

# Update and upgrade system
sudo apt update && sudo apt upgrade -y

# Install Python and required packages
sudo apt install -y python3 python3-pip python3-venv

# Create project directory and activate virtual environment
mkdir -p "${user_home}/gmail_manager"
python3 -m venv "${user_home}/gmail_manager/gmail_env"
source "${user_home}/gmail_manager/gmail_env/bin/activate"

# Install required Python libraries
pip install --upgrade google-auth-oauthlib google-auth-httplib2 google-api-python-client python-dateutil email-validator  google-auth

# Verify installation
python3 -c "import google_auth_oauthlib, google_auth_httplib2, googleapiclient, dateutil, email_validator; print('Libraries installed successfully')"

# Create project subdirectories
mkdir -p "${user_home}/gmail_manager/account1" "${user_home}/gmail_manager/account2" "${user_home}/gmail_manager/account3"
cd "${user_home}/gmail_manager"

# Create accounts.txt file
echo "${user_home}/gmail_manager/account1
${user_home}/gmail_manager/account2
${user_home}/gmail_manager/account3" > accounts.txt

# List of account directories
accounts=("account1" "account2" "account3")

# Loop through each account and ask if the user wants to create credentials.json
for account in "${accounts[@]}"; do
    read -p "Do you want to create credentials.json for $account? (Y/N): " create_credentials

    if [[ $create_credentials =~ ^[Yy]$ ]]; then
        cd "${user_home}/gmail_manager/$account"
        nano credentials.json
        echo "credentials.json has been created and saved in $account folder."
        echo "Please copy and paste the authorization code back into the terminal to proceed."
        cd "${user_home}/gmail_manager"
    else
        echo "Skipping credentials.json setup for $account."
    fi
done

# Create necessary files
touch scan_senders.txt exception_do_not_delete.txt scanned_email_list.txt del_emails_record.txt already_emailed.txt draft_emails.txt

# Populate scan_senders.txt with keywords
echo "keyword:offer
keyword:promotion
keyword:news
keyword:" > scan_senders.txt

# Set correct permissions
chmod 600 scan_senders.txt exception_do_not_delete.txt scanned_email_list.txt already_emailed.txt draft_emails.txt

# Ask the user to specify job titles in scanned_email_list.txt
echo "Please specify the job titles you want to look for in the inbox."
nano scanned_email_list.txt

# Ask the user for a response message to job postings
echo "Please enter the full response message you would like to send to job postings found in the inbox."
read -p "Response message: " reply_message

# Create the Python script (gmail_manager.py)
cat << 'EOF' > gmail_manager.py
import os
import pickle
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import logging
from logging.handlers import RotatingFileHandler
from googleapiclient.errors import HttpError
import base64

# Set up logging
log_file = f'{os.path.expanduser("~")}/gmail_manager/gmail_manager.log'
handler = RotatingFileHandler(log_file, maxBytes=10000, backupCount=1)
logging.basicConfig(handlers=[handler], level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

SCOPES = ['https://mail.google.com/']
scan_senders_FILE = f'{os.path.expanduser("~")}/gmail_manager/scan_senders.txt'
EXCEPTION_FILE = f'{os.path.expanduser("~")}/gmail_manager/exception_do_not_delete.txt'
ALREADY_EMAILED_FILE = f'{os.path.expanduser("~")}/gmail_manager/already_emailed.txt'
ACCOUNTS_FILE = f'{os.path.expanduser("~")}/gmail_manager/accounts.txt'
DELETION_RECORD_FILE = f'{os.path.expanduser("~")}/gmail_manager/del_emails_record.txt'

def get_gmail_service(account_dir):
    creds = None
    token_path = os.path.join(account_dir, 'token.pickle')
    credentials_path = os.path.join(account_dir, 'credentials.json')
    
    if os.path.exists(token_path):
        with open(token_path, 'rb') as token:
            creds = pickle.load(token)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not os.path.exists(credentials_path):
                logging.error(f"The file 'credentials.json' is missing in {account_dir}.")
                return None
            flow = Flow.from_client_secrets_file(credentials_path, SCOPES)
            flow.redirect_uri = 'urn:ietf:wg:oauth:2.0:oob'
            auth_url, _ = flow.authorization_url(prompt='consent')
            print(f'Please visit this URL to authorize the application: {auth_url}')
            code = input('Enter the authorization code: ')
            flow.fetch_token(code=code)
            creds = flow.credentials
            with open(token_path, 'wb') as token:
                pickle.dump(creds, token)
    return build('gmail', 'v1', credentials=creds)

def load_scan_senders_and_keywords():
    if not os.path.exists(scan_senders_FILE):
        open(scan_senders_FILE, 'w').close()
    
    with open(scan_senders_FILE, 'r') as f:
        lines = f.read().splitlines()
    
    scan_senders = set()
    keywords = set()
    
    for line in lines:
        if line.startswith('keyword:'):
            keywords.add(line[8:].strip().lower())
        else:
            scan_senders.add(line.strip().lower())
    
    return scan_senders, keywords

def load_exceptions():
    if not os.path.exists(EXCEPTION_FILE):
        open(EXCEPTION_FILE, 'w').close()
    
    with open(EXCEPTION_FILE, 'r') as f:
        return set(line.strip().lower() for line in f.read().splitlines())

def should_delete_email(subject, from_email, scan_senders, keywords, exceptions):
    from_lower = from_email.lower()
    
    # Check exceptions first
    if from_lower in exceptions:
        return False
    
    # Check blocked senders and keywords
    subject_lower = subject.lower()
    if any(sender in from_lower for sender in scan_senders):
        return True
    
    if any(keyword in subject_lower or keyword in from_lower for keyword in keywords):
        return True
    
    return False

def get_email_details(service, message_id):
    try:
        message = service.users().messages().get(userId='me', id=message_id, format='full').execute()
        headers = message['payload']['headers']
        
        subject = next((header['value'] for header in headers if header['name'].lower() == 'subject'), 'No Subject')
        from_email = next((header['value'] for header in headers if header['name'].lower() == 'from'), 'No Sender')
        
        return subject, from_email
    except HttpError as error:
        logging.error(f'Error getting email details for message {message_id}: {error}')
        return None, None

def update_deletion_record(sender):
    """Update the count of deleted emails for a given sender in 'del_emails_record.txt'."""
    sender = sender.lower()
    deletion_counts = {}

    # Load existing data from the deletion record file
    if os.path.exists(DELETION_RECORD_FILE):
        with open(DELETION_RECORD_FILE, 'r') as f:
            for line in f:
                parts = line.strip().split(',')
                
                # Ensure line is correctly formatted
                if len(parts) == 2:
                    email, count = parts
                    deletion_counts[email] = int(count)
                else:
                    logging.warning(f"Skipping malformed line in deletion record: {line.strip()}")

    # Update the deletion count for the sender
    deletion_counts[sender] = deletion_counts.get(sender, 0) + 1

    # Write updated counts back to the file
    with open(DELETION_RECORD_FILE, 'w') as f:
        for email, count in deletion_counts.items():
            f.write(f"{email},{count}\n")

def delete_email(service, message_id, from_email):
    try:
        service.users().messages().trash(userId='me', id=message_id).execute()
        update_deletion_record(from_email)
        return True
    except HttpError as error:
        logging.error(f'Error deleting email {message_id}: {error}')
        return False

def remove_unstarred_exception(service, label_ids, exceptions):
    """Remove unstarred exception emails from inbox and other categories, and update exception and already emailed files."""
    exception_emails_to_remove = set()
    
    for label_id in label_ids:
        try:
            results = service.users().messages().list(userId='me', labelIds=[label_id]).execute()
            messages = results.get('messages', [])
            
            for message in messages:
                msg_id = message['id']
                _, from_email = get_email_details(service, msg_id)
                
                if from_email and from_email.lower() in exceptions:
                    message_labels = service.users().messages().get(userId='me', id=msg_id, format='minimal').execute()['labelIds']
                    
                    if 'STARRED' not in message_labels:
                        if delete_email(service, msg_id, from_email):
                            exception_emails_to_remove.add(from_email.lower())
                            logging.info(f"Removed unstarred exception email: {from_email}")

        except HttpError as error:
            logging.error(f"Error checking unstarred exceptions in label {label_id}: {error}")
            break
    
    if exception_emails_to_remove:
        update_exception_file(exception_emails_to_remove)
        update_already_emailed_file(exception_emails_to_remove)

def update_exception_file(emails_to_remove):
    """Update the exception file by removing specified emails."""
    if not os.path.exists(EXCEPTION_FILE):
        return

    with open(EXCEPTION_FILE, 'r') as f:
        exceptions = set(line.strip().lower() for line in f)

    with open(EXCEPTION_FILE, 'w') as f:
        for email in exceptions - emails_to_remove:
            f.write(f"{email}\n")

def update_already_emailed_file(emails_to_remove):
    """Update the already emailed file by removing specified emails."""
    if not os.path.exists(ALREADY_EMAILED_FILE):
        return

    with open(ALREADY_EMAILED_FILE, 'r') as f:
        already_emailed = set(line.strip().lower() for line in f)

    with open(ALREADY_EMAILED_FILE, 'w') as f:
        for email in already_emailed - emails_to_remove:
            f.write(f"{email}\n")

def process_emails(service, label_ids, account_dir, scan_senders, keywords, exceptions):
    page_token = None

    while True:
        try:
            # List all messages in the given label (includes both read and unread)
            results = service.users().messages().list(userId='me', labelIds=label_ids, pageToken=page_token).execute()
            messages = results.get('messages', [])
            
            if not messages:
                logging.info(f"No more messages found in the specified label for account {account_dir}.")
                break

            for message in messages:
                msg_id = message['id']
                subject, from_email = get_email_details(service, msg_id)
                
                if subject is None:
                    continue
                
                message_labels = service.users().messages().get(userId='me', id=msg_id, format='minimal').execute()['labelIds']
                
                if 'STARRED' in message_labels:
                    add_to_exceptions(from_email)
                    logging.info(f"Added {from_email} to exceptions (starred)")
                elif should_delete_email(subject, from_email, scan_senders, keywords, exceptions):
                    if delete_email(service, msg_id, from_email):
                        logging.info(f"Deleted email: {subject} from {from_email} for account {account_dir}")

            page_token = results.get('nextPageToken')
            if not page_token:
                break

        except HttpError as error:
            logging.error(f'An error occurred while processing emails for account {account_dir}: {error}')
            break

def add_to_exceptions(email):
    with open(EXCEPTION_FILE, 'a+') as f:
        f.seek(0)
        existing_exceptions = set(f.read().splitlines())
        if email.lower() not in existing_exceptions:
            f.write(f"{email.lower()}\n")

def process_account(account_dir):
    service = get_gmail_service(account_dir)
    if not service:
        return

    scan_senders, keywords = load_scan_senders_and_keywords()
    exceptions = load_exceptions()
    
    # Remove unstarred exception emails first
    remove_unstarred_exception(service, ['INBOX', 'CATEGORY_PROMOTIONS', 'CATEGORY_UPDATES'], exceptions)
    
    # Process emails in the inbox
    process_emails(service, ['INBOX'], account_dir, scan_senders, keywords, exceptions)
    
    # Process emails in the promotions category
    process_emails(service, ['CATEGORY_PROMOTIONS'], account_dir, scan_senders, keywords, exceptions)
    
    # Process emails in the updates category
    process_emails(service, ['CATEGORY_UPDATES'], account_dir, scan_senders, keywords, exceptions)

def main():
    if not os.path.exists(ACCOUNTS_FILE):
        logging.error(f"The accounts file '{ACCOUNTS_FILE}' is missing.")
        return

    with open(ACCOUNTS_FILE, 'r') as f:
        account_dirs = f.read().splitlines()

    for account_dir in account_dirs:
        if os.path.exists(account_dir):
            logging.info(f"Processing account: {account_dir}")
            process_account(account_dir)
        else:
            logging.error(f"Account directory '{account_dir}' does not exist.")

if __name__ == '__main__':
    main()
EOF

# Create Script B (email_scanner.py)
cat << EOF > email_scanner.py
import os
import pickle
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import logging
from logging.handlers import RotatingFileHandler
from googleapiclient.errors import HttpError
import time
import random
import base64
from email_validator import validate_email, EmailNotValidError
import re
from email.mime.text import MIMEText

# Set up logging
log_file = f'{os.path.expanduser("~")}/gmail_manager/email_scan.log'
handler = RotatingFileHandler(log_file, maxBytes=10000, backupCount=1)
logging.basicConfig(handlers=[handler], level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

SCOPES = ['https://mail.google.com/']
SCANNED_EMAIL_LIST_FILE = f'{os.path.expanduser("~")}/gmail_manager/scanned_email_list.txt'
ALREADY_EMAILED_FILE = f'{os.path.expanduser("~")}/gmail_manager/already_emailed.txt'
DRAFT_EMAILS_FILE = f'{os.path.expanduser("~")}/gmail_manager/draft_emails.txt'
ACCOUNTS_FILE = f'{os.path.expanduser("~")}/gmail_manager/accounts.txt'

# Rate limiting variables
REQUESTS_PER_USER_LIMIT = 250
REQUESTS_PER_PROJECT_LIMIT = 1000
REQUEST_WINDOW = 100  # seconds

user_request_count = 0
project_request_count = 0
start_time = time.time()

def ensure_directories():
  base_dir = f'{os.path.expanduser("~")}/gmail_manager'
  if not os.path.exists(base_dir):
      os.makedirs(base_dir)
  
  required_files = [
      SCANNED_EMAIL_LIST_FILE,
      ALREADY_EMAILED_FILE,
      DRAFT_EMAILS_FILE,
      ACCOUNTS_FILE
  ]
  
  for file in required_files:
      if not os.path.exists(file):
          with open(file, 'w') as f:
              pass

def rate_limit():
  global user_request_count, project_request_count, start_time
  current_time = time.time()
  elapsed_time = current_time - start_time

  if elapsed_time > REQUEST_WINDOW:
      user_request_count = 0
      project_request_count = 0
      start_time = current_time

  if user_request_count >= REQUESTS_PER_USER_LIMIT or project_request_count >= REQUESTS_PER_PROJECT_LIMIT:
      sleep_time = REQUEST_WINDOW - elapsed_time
      logging.info(f"Rate limit reached. Sleeping for {sleep_time:.2f} seconds.")
      time.sleep(sleep_time)
      user_request_count = 0
      project_request_count = 0
      start_time = time.time()

def execute_with_backoff(request):
  global user_request_count, project_request_count
  max_retries = 5
  for n in range(max_retries):
      try:
          rate_limit()
          response = request.execute()
          user_request_count += 1
          project_request_count += 1
          return response
      except HttpError as error:
          if error.resp.status in [403, 429]:
              wait_time = (2 ** n) + random.uniform(0, 1)
              logging.warning(f"Rate limit exceeded. Retrying in {wait_time:.2f} seconds...")
              time.sleep(wait_time)
          else:
              raise
  logging.error("Max retries exceeded.")
  return None

def get_gmail_service(account_dir):
  creds = None
  token_path = os.path.join(account_dir, 'token.pickle')
  credentials_path = os.path.join(account_dir, 'credentials.json')
  
  if os.path.exists(token_path):
      with open(token_path, 'rb') as token:
          creds = pickle.load(token)
  if not creds or not creds.valid:
      if creds and creds.expired and creds.refresh_token:
          creds.refresh(Request())
      else:
          if not os.path.exists(credentials_path):
              logging.error(f"The file 'credentials.json' is missing in {account_dir}.")
              return None
          flow = Flow.from_client_secrets_file(credentials_path, SCOPES)
          flow.redirect_uri = 'urn:ietf:wg:oauth:2.0:oob'
          auth_url, _ = flow.authorization_url(prompt='consent')
          print(f'Please visit this URL to authorize the application: {auth_url}')
          code = input('Enter the authorization code: ')
          flow.fetch_token(code=code)
          creds = flow.credentials
          with open(token_path, 'wb') as token:
              pickle.dump(creds, token)
  return build('gmail', 'v1', credentials=creds)

def load_keywords():
  try:
      with open(SCANNED_EMAIL_LIST_FILE, 'r') as f:
          return [keyword.strip().lower() for keyword in f.readlines()]
  except Exception as e:
      logging.error(f"Error loading keywords: {str(e)}")
      return []

def load_already_emailed():
  try:
      if not os.path.exists(ALREADY_EMAILED_FILE):
          open(ALREADY_EMAILED_FILE, 'w').close()
      with open(ALREADY_EMAILED_FILE, 'r') as f:
          return set(line.strip() for line in f.readlines())
  except Exception as e:
      logging.error(f"Error loading already emailed list: {str(e)}")
      return set()

def load_draft_emails():
  try:
      if not os.path.exists(DRAFT_EMAILS_FILE):
          open(DRAFT_EMAILS_FILE, 'w').close()
      with open(DRAFT_EMAILS_FILE, 'r') as f:
          return set(line.strip() for line in f.readlines())
  except Exception as e:
      logging.error(f"Error loading draft emails list: {str(e)}")
      return set()

def check_email_content(service, msg_id, keywords):
  try:
      message = execute_with_backoff(service.users().messages().get(userId='me', id=msg_id, format='full'))
      if not message:
          return False

      subject = ''
      body = ''

      # Extract subject
      for header in message['payload']['headers']:
          if header['name'].lower() == 'subject':
              subject = header['value'].lower()
              break

      # Extract body
      if 'parts' in message['payload']:
          for part in message['payload']['parts']:
              if part['mimeType'] == 'text/plain':
                  body = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8').lower()
                  break
      elif 'body' in message['payload']:
          body = base64.urlsafe_b64decode(message['payload']['body']['data']).decode('utf-8').lower()

      # Check if any keyword is in subject or body
      return any(keyword in subject or keyword in body for keyword in keywords)

  except HttpError as error:
      logging.error(f'Error checking email content for message {msg_id}: {error}')
      return False

def star_email(service, msg_id):
  try:
      execute_with_backoff(service.users().messages().modify(
          userId='me',
          id=msg_id,
          body={'addLabelIds': ['STARRED']}
      ))
      logging.info(f"Starred email: {msg_id}")
  except HttpError as error:
      logging.error(f'Error starring email {msg_id}: {error}')

def unstar_email(service, msg_id):
  try:
      execute_with_backoff(service.users().messages().modify(
          userId='me',
          id=msg_id,
          body={'removeLabelIds': ['STARRED']}
      ))
      logging.info(f"Unstarred email: {msg_id}")
  except HttpError as error:
      logging.error(f'Error unstarring email {msg_id}: {error}')

def validate_email_address(email):
  try:
      validate_email(email, check_deliverability=True)
      return True
  except EmailNotValidError as e:
      logging.warning(f"Invalid email address: {email}. Error: {str(e)}")
      return False

def create_draft(service, msg_id, to_email, subject, reply_message):
  if not validate_email_address(to_email):
      logging.info(f"Skipping draft creation for invalid email: {to_email}")
      unstar_email(service, msg_id)
      return False

  # Check if email is in draft_emails or already_emailed
  draft_emails = load_draft_emails()
  already_emailed = load_already_emailed()

  if to_email in already_emailed:
      logging.info(f"Email {to_email} already processed, skipping.")
      return False

  if to_email in draft_emails:
      logging.info(f"Draft already exists for {to_email}, skipping.")
      return False

  try:
      thread_id = execute_with_backoff(service.users().messages().get(
          userId='me', 
          id=msg_id, 
          format='metadata'
      ))['threadId']
      
      message = MIMEText(reply_message)
      message['to'] = to_email
      message['subject'] = f'Re: {subject}'
      
      raw_message = base64.urlsafe_b64encode(
          message.as_bytes()
      ).decode('utf-8')

      draft = {
          'message': {
              'threadId': thread_id,
              'raw': raw_message
          }
      }

      execute_with_backoff(service.users().drafts().create(userId='me', body=draft))
      logging.info(f"Created draft for email: {to_email}")

      # Add email to draft_emails.txt
      with open(DRAFT_EMAILS_FILE, 'a') as f:
          f.write(f"{to_email}\n")

      return True

  except HttpError as error:
      logging.error(f'Error creating draft for email {msg_id}: {error}')
      return False

def extract_email_address(from_header):
  match = re.search(r'<(.+?)>', from_header)
  if match:
      return match.group(1)
  return from_header.strip()

def process_emails(service, account_dir, reply_message):
  keywords = load_keywords()
  already_emailed = load_already_emailed()
  
  try:
      results = execute_with_backoff(service.users().messages().list(userId='me', labelIds=['INBOX']))
      if not results:
          return

      messages = results.get('messages', [])
      
      for message in messages:
          msg_id = message['id']
          full_message = execute_with_backoff(service.users().messages().get(userId='me', id=msg_id, format='full'))
          from_header = next((header for header in full_message['payload']['headers'] if header['name'].lower() == 'from'), None)
          if from_header:
              from_email = extract_email_address(from_header['value'])
              if from_email in already_emailed:
                  logging.info(f"Already processed {from_email}, skipping.")
                  continue

          if check_email_content(service, msg_id, keywords):
              star_email(service, msg_id)
              subject = next((header['value'] for header in full_message['payload']['headers'] if header['name'].lower() == 'subject'), "No Subject")
              if create_draft(service, msg_id, from_email, subject, reply_message):
                  logging.info(f"Successfully created draft for {from_email}")
              else:
                  logging.info(f"Failed to create draft for {from_email}")

  except HttpError as error:
      logging.error(f'An error occurred while processing emails for account {account_dir}: {error}')

def check_sent_label(service, email_address):
  try:
      query = f'to:{email_address} in:sent'
      results = execute_with_backoff(service.users().messages().list(
          userId='me',
          q=query,
          maxResults=1
      ))
      return bool(results.get('messages', []))
  except HttpError as error:
      logging.error(f'Error checking sent label for {email_address}: {error}')
      return False

def process_draft_to_sent(service):
  draft_emails = load_draft_emails()
  if not draft_emails:
      return

  moved_emails = set()
  
  for email in draft_emails:
      if check_sent_label(service, email):
          # Add to already_emailed.txt
          with open(ALREADY_EMAILED_FILE, 'a') as f:
              f.write(f"{email}\n")
          moved_emails.add(email)
          logging.info(f"Moved {email} from draft to already emailed")

  # Remove moved emails from draft_emails.txt
  remaining_drafts = draft_emails - moved_emails
  with open(DRAFT_EMAILS_FILE, 'w') as f:
      f.write('\n'.join(remaining_drafts) + '\n' if remaining_drafts else '')

def remove_duplicates_from_file(filename):
  try:
      # Read all lines and remove duplicates while preserving order
      with open(filename, 'r') as f:
          lines = f.readlines()
      
      # Remove whitespace and empty lines
      lines = [line.strip() for line in lines if line.strip()]
      
      # Remove duplicates while preserving order
      seen = set()
      unique_lines = []
      for line in lines:
          if line not in seen:
              seen.add(line)
              unique_lines.append(line)
      
      # Write back the unique lines
      with open(filename, 'w') as f:
          f.write('\n'.join(unique_lines) + '\n' if unique_lines else '')
      
      logging.info(f"Removed {len(lines) - len(unique_lines)} duplicate entries from {filename}")
  except Exception as e:
      logging.error(f"Error removing duplicates from file {filename}: {str(e)}")

def main():
  ensure_directories()

  # Remove duplicates from both files at startup
  remove_duplicates_from_file(ALREADY_EMAILED_FILE)
  remove_duplicates_from_file(DRAFT_EMAILS_FILE)

  if not os.path.exists(ACCOUNTS_FILE):
      logging.error(f"The accounts file '{ACCOUNTS_FILE}' is missing.")
      return

  reply_message = """I'm interested in this Position.Please find my cover letter, resume and Linkedin.And If you a Recruiter and need RT and Rate confirmation email from me.Please kindly resend me the Job description along with Offered Rate email first .Then call me between 2pm-4pm EST Mon-Fri.   
  
   Cover_Letter:
   https://drive.google.com/drive/folders/1rH0rosdJJ6X9h3SB7vMImZpd9hHmTjxb?usp=drive_link
   
   Latest_Resume:
   https://drive.google.com/drive/folders/1PtmneST0ItJIzLmj36-l60zRvGPTyGes?usp=drive_link

   Linkedin Profile:
   www.linkedin.com/in/zeeshan-sibtain-76680631b

   
   Best,
   Zeeshan Sibtain"""

  try:
      with open(ACCOUNTS_FILE, 'r') as f:
          account_dirs = f.read().splitlines()

      if not account_dirs:
          logging.error("No accounts found in accounts.txt")
          return

      for account_dir in account_dirs:
          if os.path.exists(account_dir):
              logging.info(f"Processing account: {account_dir}")
              service = get_gmail_service(account_dir)
              if service:
                  # Process draft to sent first
                  process_draft_to_sent(service)
                  # Then process new emails
                  process_emails(service, account_dir, reply_message)
          else:
              logging.error(f"Account directory '{account_dir}' does not exist.")

      # Remove duplicates again after processing
      remove_duplicates_from_file(ALREADY_EMAILED_FILE)
      remove_duplicates_from_file(DRAFT_EMAILS_FILE)

  except Exception as e:
      logging.error(f"An error occurred in main: {str(e)}")

if __name__ == '__main__':
  main()
EOF

# Set correct permissions for the Python scripts
chmod 600 gmail_manager.py email_scanner.py

# Create a script to run the Python script with the virtual environment
cat << EOF > run_gmail_manager.sh
#!/bin/bash
cd "${user_home}/gmail_manager"
source "${user_home}/gmail_manager/gmail_env/bin/activate"
python3 gmail_manager.py
EOF

# Create a script to run Script B with the virtual environment
cat << EOF > run_email_scanner.sh
#!/bin/bash
cd "${user_home}/gmail_manager"
source "${user_home}/gmail_manager/gmail_env/bin/activate"
python3 email_scanner.py
EOF

# Make the run scripts executable
chmod 700 run_gmail_manager.sh run_email_scanner.sh

# Automatically execute the run_gmail_manager.sh script
./run_gmail_manager.sh

# Prompt user to paste the authorization code
echo "Please complete the authentication process for each account. Once done, the email scanner will run automatically."

# Automatically execute the run_email_scanner.sh script
./run_email_scanner.sh

# Prompt user for timer settings
read -p "Enter OnBootSec in minutes: " on_boot_min
read -p "Enter OnUnitActiveSec in hours: " on_unit_active_hr

# Convert user input to the correct format
on_boot_sec="${on_boot_min}min"
on_unit_active_sec="${on_unit_active_hr}hr"

# Create the systemd service file for gmail_manager
sudo bash -c "cat << EOF > /etc/systemd/system/gmail_manager.service
[Unit]
Description=Gmail Manager Service
After=network.target

[Service]
ExecStart=/bin/bash ${user_home}/gmail_manager/run_gmail_manager.sh
User=$(whoami)
Group=$(whoami)
WorkingDirectory=${user_home}/gmail_manager

[Install]
WantedBy=multi-user.target
EOF"

# Create the systemd timer file for gmail_manager with user input
sudo bash -c "cat << EOF > /etc/systemd/system/gmail_manager.timer
[Unit]
Description=Run Gmail Manager every specified interval

[Timer]
OnBootSec=${on_boot_sec}
OnUnitActiveSec=${on_unit_active_sec}

[Install]
WantedBy=timers.target
EOF"

# Create the systemd service file for email_scanner
sudo bash -c "cat << EOF > /etc/systemd/system/email_scanner.service
[Unit]
Description=Email Scanner Service
After=network.target

[Service]
ExecStart=/bin/bash ${user_home}/gmail_manager/run_email_scanner.sh
User=$(whoami)
Group=$(whoami)
WorkingDirectory=${user_home}/gmail_manager

[Install]
WantedBy=multi-user.target
EOF"

# Create the systemd timer file for email_scanner
sudo bash -c "cat << EOF > /etc/systemd/system/email_scanner.timer
[Unit]
Description=Run Email Scanner every 10 minutes

[Timer]
OnBootSec=1min
OnUnitActiveSec=10min

[Install]
WantedBy=timers.target
EOF"

# Set proper permissions
sudo chmod 644 /etc/systemd/system/gmail_manager.service
sudo chmod 644 /etc/systemd/system/gmail_manager.timer
sudo chmod 644 /etc/systemd/system/email_scanner.service
sudo chmod 644 /etc/systemd/system/email_scanner.timer

# Reload systemd to recognize the new services and timers
sudo systemctl daemon-reload

# Enable and start the timers
sudo systemctl enable gmail_manager.timer
sudo systemctl start gmail_manager.timer
sudo systemctl enable email_scanner.timer
sudo systemctl start email_scanner.timer

# Check the status of the timers
sudo systemctl status gmail_manager.timer
sudo systemctl status email_scanner.timer

# List all timers to verify
sudo systemctl list-timers

# Reminder for manual steps
echo "Setup complete! Please remember to do the following manual steps:"
echo "1. Place your credentials.json file in each account directory (${user_home}/gmail_manager/account1, ${user_home}/gmail_manager/account2, ${user_home}/gmail_manager/account3)"
echo "2. Run the scripts manually once to authenticate:"
echo "   ./run_gmail_manager.sh"
echo "   ./run_email_scanner.sh"
echo "3. When prompted, visit the authorization URL in a browser, then copy and paste the authorization code back into the terminal"
echo "4. Check ${user_home}/gmail_manager/gmail_manager.log and ${user_home}/gmail_manager/email_scan.log for any errors"

# Tail the log files for errors
echo "Tailing log files for errors. Press Ctrl+C to exit."
tail -f "${user_home}/gmail_manager/gmail_manager.log" "${user_home}/gmail_manager/email_scan.log"