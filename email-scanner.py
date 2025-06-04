import os
import pickle
from google_auth_oauthlib.flow import InstalledAppFlow
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
BASE_DIR = f'{os.path.expanduser("~")}/gmail_manager'
log_file = f'{BASE_DIR}/email_scan.log'
os.makedirs(os.path.dirname(log_file), exist_ok=True)
handler = RotatingFileHandler(log_file, maxBytes=10000, backupCount=3)
logging.basicConfig(handlers=[handler], level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

SCOPES = ['https://mail.google.com/']
SCANNED_EMAIL_LIST_FILE = f'{BASE_DIR}/scanned_email_list.txt'
ALREADY_EMAILED_FILE = f'{BASE_DIR}/already_emailed.txt'
DRAFT_EMAILS_FILE = f'{BASE_DIR}/draft_emails.txt'
ACCOUNTS_FILE = f'{BASE_DIR}/accounts.txt'

# Rate limiting variables
REQUESTS_PER_USER_LIMIT = 250
REQUESTS_PER_PROJECT_LIMIT = 1000
REQUEST_WINDOW = 100  # seconds

user_request_count = 0
project_request_count = 0
start_time = time.time()

def ensure_directories():
    """Create necessary directories and files if they don't exist"""
    if not os.path.exists(BASE_DIR):
        os.makedirs(BASE_DIR)
    
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
            logging.info(f"Created empty file: {file}")

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
                logging.error(f"HTTP Error: {error}")
                raise
    logging.error("Max retries exceeded.")
    return None

def test_service_connection(service):
    """Test if the Gmail API connection works"""
    try:
        # Try to fetch profile to test connection
        profile = execute_with_backoff(service.users().getProfile(userId='me'))
        if profile and 'emailAddress' in profile:
            logging.info(f"Successfully connected to Gmail API for: {profile['emailAddress']}")
            return True
        else:
            logging.warning("Connected to API but couldn't retrieve profile information")
            return False
    except HttpError as error:
        logging.error(f"Failed to connect to Gmail API: {error}")
        return False

def get_gmail_service(account_dir):
    """Get authenticated Gmail service with proper token handling"""
    creds = None
    token_path = os.path.join(account_dir, 'token.pickle')
    credentials_path = os.path.join(account_dir, 'credentials.json')
    
    # Create account directory if it doesn't exist
    if not os.path.exists(account_dir):
        logging.info(f"Creating account directory: {account_dir}")
        os.makedirs(account_dir)
    
    # Load existing token if available
    if os.path.exists(token_path):
        try:
            with open(token_path, 'rb') as token:
                creds = pickle.load(token)
            logging.info("Loaded existing token")
        except Exception as e:
            logging.error(f"Error loading token: {str(e)}")
            # If token is corrupted, remove it
            os.remove(token_path)
            creds = None
    
    # Check if credentials need refreshing or new auth flow
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                logging.info("Refreshing expired token")
                creds.refresh(Request())
                logging.info("Token refreshed successfully")
            except Exception as e:
                logging.error(f"Error refreshing token: {str(e)}")
                creds = None  # Force new authentication flow
        
        # Need new authentication flow
        if not creds:
            if not os.path.exists(credentials_path):
                logging.error(f"The file 'credentials.json' is missing in {account_dir}.")
                return None
            
            try:
                logging.info("Starting new authentication flow")
                flow = InstalledAppFlow.from_client_secrets_file(
                    credentials_path, 
                    SCOPES,
                    redirect_uri='urn:ietf:wg:oauth:2.0:oob'
                )
                # Use offline access type to get refresh token and force consent screen
                auth_url, _ = flow.authorization_url(access_type='offline', prompt='consent')
                print(f'Please visit this URL to authorize the application: {auth_url}')
                code = input('Enter the authorization code: ')
                flow.fetch_token(code=code)
                creds = flow.credentials
                logging.info("New authentication successful")
                
                # Save the credentials
                try:
                    with open(token_path, 'wb') as token:
                        pickle.dump(creds, token)
                    logging.info(f"Token saved to {token_path}")
                except Exception as e:
                    logging.error(f"Error saving token: {str(e)}")
            except Exception as e:
                logging.error(f"Authentication error: {str(e)}")
                return None
    
    try:
        service = build('gmail', 'v1', credentials=creds)
        
        # Test the connection
        if test_service_connection(service):
            return service
        else:
            # If test failed but no exception was raised, try re-authenticating
            logging.warning("Connection test failed. Attempting re-authentication.")
            os.remove(token_path)
            return get_gmail_service(account_dir)  # Recursive call to start fresh
    except Exception as e:
        logging.error(f"Error building Gmail service: {str(e)}")
        return None

def load_keywords():
    try:
        with open(SCANNED_EMAIL_LIST_FILE, 'r') as f:
            return [keyword.strip().lower() for keyword in f.readlines() if keyword.strip()]
    except Exception as e:
        logging.error(f"Error loading keywords: {str(e)}")
        return []

def load_already_emailed():
    try:
        if not os.path.exists(ALREADY_EMAILED_FILE):
            open(ALREADY_EMAILED_FILE, 'w').close()
        with open(ALREADY_EMAILED_FILE, 'r') as f:
            return set(line.strip() for line in f.readlines() if line.strip())
    except Exception as e:
        logging.error(f"Error loading already emailed list: {str(e)}")
        return set()

def load_draft_emails():
    try:
        if not os.path.exists(DRAFT_EMAILS_FILE):
            open(DRAFT_EMAILS_FILE, 'w').close()
        with open(DRAFT_EMAILS_FILE, 'r') as f:
            return set(line.strip() for line in f.readlines() if line.strip())
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
                    body = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8', errors='replace').lower()
                    break
        elif 'body' in message['payload']:
            body = base64.urlsafe_b64decode(message['payload']['body']['data']).decode('utf-8', errors='replace').lower()

        # Check if any keyword is in subject or body
        return any(keyword in subject or keyword in body for keyword in keywords)

    except HttpError as error:
        logging.error(f'Error checking email content for message {msg_id}: {error}')
        return False
    except Exception as e:
        logging.error(f'Unexpected error checking email content for message {msg_id}: {str(e)}')
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
    
    if not keywords:
        logging.warning("No keywords loaded. Please add keywords to scan for in the scanned_email_list.txt file.")
        return
    
    try:
        results = execute_with_backoff(service.users().messages().list(userId='me', labelIds=['INBOX']))
        if not results:
            logging.info("No messages found in inbox")
            return

        messages = results.get('messages', [])
        logging.info(f"Found {len(messages)} messages to process")
        
        for message in messages:
            msg_id = message['id']
            try:
                full_message = execute_with_backoff(service.users().messages().get(userId='me', id=msg_id, format='full'))
                if not full_message or 'payload' not in full_message or 'headers' not in full_message['payload']:
                    logging.warning(f"Skipping message {msg_id}: Invalid message format")
                    continue
                
                from_header = next((header for header in full_message['payload']['headers'] if header['name'].lower() == 'from'), None)
                if not from_header:
                    logging.warning(f"Skipping message {msg_id}: No 'From' header found")
                    continue
                
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
            except Exception as e:
                logging.error(f"Error processing message {msg_id}: {str(e)}")
                continue

    except HttpError as error:
        logging.error(f'An error occurred while processing emails for account {account_dir}: {error}')
    except Exception as e:
        logging.error(f'Unexpected error processing emails for account {account_dir}: {str(e)}')

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
        logging.info("No draft emails to process")
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
        if not os.path.exists(filename) or os.path.getsize(filename) == 0:
            logging.info(f"File {filename} is empty or doesn't exist. No duplicates to remove.")
            return
            
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
    try:
        # Ensure all directories and files exist
        ensure_directories()

        # Remove duplicates from both files at startup
        remove_duplicates_from_file(ALREADY_EMAILED_FILE)
        remove_duplicates_from_file(DRAFT_EMAILS_FILE)

        if not os.path.exists(ACCOUNTS_FILE):
            logging.error(f"The accounts file '{ACCOUNTS_FILE}' is missing.")
            print(f"Error: The accounts file '{ACCOUNTS_FILE}' is missing.")
            print(f"Please create this file with one account directory per line.")
            return

        if os.path.getsize(ACCOUNTS_FILE) == 0:
            logging.error("The accounts file is empty.")
            print("Error: The accounts file is empty.")
            print("Please add at least one account directory to the file.")
            return

        reply_message = """I'm interested in this Position. Please find my cover letter, resume and Linkedin. And If you are a Recruiter and need RT and Rate confirmation email from me. Please kindly resend me the Job description along with Offered Rate email first. Then call me between 2pm-4pm EST Mon-Fri.   
    
   Cover_Letter:
   https://drive.google.com/drive/folders/1rH0rosdJJ6X9h3SB7vMImZpd9hHmTjxb?usp=drive_link
   
   Latest_Resume:
   https://drive.google.com/drive/folders/1PtmneST0ItJIzLmj36-l60zRvGPTyGes?usp=drive_link

   Linkedin Profile:
   www.linkedin.com/in/zeeshan-sibtain-76680631b

   
   Best,
   Zeeshan Sibtain"""

        with open(ACCOUNTS_FILE, 'r') as f:
            account_dirs = [line.strip() for line in f.read().splitlines() if line.strip()]

        if not account_dirs:
            logging.error("No valid accounts found in accounts.txt")
            print("Error: No valid accounts found in accounts.txt")
            return

        for account_dir in account_dirs:
            logging.info(f"Processing account: {account_dir}")
            # Ensure account directory exists
            os.makedirs(account_dir, exist_ok=True)
            
            service = get_gmail_service(account_dir)
            if service:
                # Process draft to sent first
                process_draft_to_sent(service)
                # Then process new emails
                process_emails(service, account_dir, reply_message)
            else:
                logging.error(f"Failed to get Gmail service for account: {account_dir}")

        # Remove duplicates again after processing
        remove_duplicates_from_file(ALREADY_EMAILED_FILE)
        remove_duplicates_from_file(DRAFT_EMAILS_FILE)

        logging.info("Email scanning completed successfully")

    except Exception as e:
        logging.error(f"An error occurred in main: {str(e)}")
        print(f"Error: {str(e)}")

if __name__ == '__main__':
    main()
