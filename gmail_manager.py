import os
import pickle
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import logging
from logging.handlers import RotatingFileHandler
from googleapiclient.errors import HttpError
import base64
from datetime import datetime, timedelta

# Set up logging
home_dir = os.path.expanduser("~")
gmail_manager_dir = os.path.join(home_dir, 'gmail_manager')
os.makedirs(gmail_manager_dir, exist_ok=True)

log_file = os.path.join(gmail_manager_dir, 'gmail_manager.log')
handler = RotatingFileHandler(log_file, maxBytes=10000, backupCount=1)
logging.basicConfig(handlers=[handler], level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# These scopes request offline access which is needed for refresh tokens
SCOPES = ['https://mail.google.com/']
scan_senders_FILE = os.path.join(gmail_manager_dir, 'scan_senders.txt')
EXCEPTION_FILE = os.path.join(gmail_manager_dir, 'exception_do_not_delete.txt')
ALREADY_EMAILED_FILE = os.path.join(gmail_manager_dir, 'already_emailed.txt')
ACCOUNTS_FILE = os.path.join(gmail_manager_dir, 'accounts.txt')
DELETION_RECORD_FILE = os.path.join(gmail_manager_dir, 'del_emails_record.txt')

def get_gmail_service(account_dir):
    creds = None
    token_path = os.path.join(account_dir, 'token.pickle')
    credentials_path = os.path.join(account_dir, 'credentials.json')
    
    if os.path.exists(token_path):
        with open(token_path, 'rb') as token:
            try:
                creds = pickle.load(token)
                logging.info(f"Loaded existing credentials from {token_path}")
            except Exception as e:
                logging.error(f"Error loading credentials from {token_path}: {e}")
                creds = None
    
    # If credentials don't exist or are invalid, try to refresh or create new ones
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                logging.info("Refreshing expired credentials")
                creds.refresh(Request())
                logging.info("Successfully refreshed credentials")
            except Exception as e:
                logging.error(f"Error refreshing credentials: {e}")
                creds = None
        
        # If refresh failed or no credentials exist, create new ones
        if not creds:
            if not os.path.exists(credentials_path):
                logging.error(f"The file 'credentials.json' is missing in {account_dir}.")
                return None
                
            try:
                logging.info(f"Setting up new credentials flow from {credentials_path}")
                flow = InstalledAppFlow.from_client_secrets_file(
                    credentials_path, 
                    SCOPES,
                    redirect_uri='urn:ietf:wg:oauth:2.0:oob'
                )
                # This ensures we get a refresh token
                auth_url, _ = flow.authorization_url(access_type='offline', prompt='consent')
                print(f'Please visit this URL to authorize the application: {auth_url}')
                print('This authorization will generate a long-lasting refresh token.')
                code = input('Enter the authorization code: ')
                flow.fetch_token(code=code)
                creds = flow.credentials
                logging.info("Successfully created new credentials with refresh token")
            except Exception as e:
                logging.error(f"Error creating new credentials: {e}")
                return None
        
        # Save the credentials for future use
        try:
            with open(token_path, 'wb') as token:
                pickle.dump(creds, token)
                logging.info(f"Saved credentials to {token_path}")
        except Exception as e:
            logging.error(f"Error saving credentials to {token_path}: {e}")
    
    try:
        service = build('gmail', 'v1', credentials=creds)
        # Test the connection to confirm credentials are working
        service.users().getProfile(userId='me').execute()
        logging.info("Successfully connected to Gmail API")
        return service
    except Exception as e:
        logging.error(f"Error building Gmail service: {e}")
        return None

def load_scan_senders_and_keywords():
    if not os.path.exists(scan_senders_FILE):
        os.makedirs(os.path.dirname(scan_senders_FILE), exist_ok=True)
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
        os.makedirs(os.path.dirname(EXCEPTION_FILE), exist_ok=True)
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
        os.makedirs(os.path.dirname(ALREADY_EMAILED_FILE), exist_ok=True)
        open(ALREADY_EMAILED_FILE, 'w').close()

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
    if not os.path.exists(EXCEPTION_FILE):
        os.makedirs(os.path.dirname(EXCEPTION_FILE), exist_ok=True)
        
    with open(EXCEPTION_FILE, 'a+') as f:
        f.seek(0)
        existing_exceptions = set(f.read().splitlines())
        if email.lower() not in existing_exceptions:
            f.write(f"{email.lower()}\n")

def process_account(account_dir):
    service = get_gmail_service(account_dir)
    if not service:
        logging.error(f"Failed to get Gmail service for account {account_dir}")
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
        os.makedirs(os.path.dirname(ACCOUNTS_FILE), exist_ok=True)
        logging.error(f"The accounts file '{ACCOUNTS_FILE}' is missing. Creating an empty one.")
        open(ACCOUNTS_FILE, 'w').close()
        return

    with open(ACCOUNTS_FILE, 'r') as f:
        account_dirs = f.read().splitlines()

    if not account_dirs:
        logging.warning("No accounts found in the accounts file.")
        return

    for account_dir in account_dirs:
        if os.path.exists(account_dir):
            logging.info(f"Processing account: {account_dir}")
            process_account(account_dir)
        else:
            logging.error(f"Account directory '{account_dir}' does not exist.")

if __name__ == '__main__':
    main()
