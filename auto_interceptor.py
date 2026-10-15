# auto_interceptor.py
import time
import requests
import imaplib
import email
from email.header import decode_header

# --- CONFIGURATION ---
EMAIL_ACCOUNT = "Feenaz24@gmail.com"  
EMAIL_PASSWORD = "ehur cbkd geso limp" 
DJANGO_WEBHOOK_URL = "http://127.0.0.1:8000/api/auto-scan/"

# Keeps track of emails we've already processed so it NEVER loops
processed_message_ids = set()

def decode_str(s):
    value, charset = decode_header(s)[0]
    if charset:
        value = value.decode(charset)
    return value

def fetch_unread_emails():
    print("🔍 Checking for new messages...")
    try:
        mail = imaplib.IMAP4_SSL("imap.gmail.com")
        mail.login(EMAIL_ACCOUNT, EMAIL_PASSWORD)
        mail.select("inbox")
        
        status, messages = mail.search(None, "UNSEEN")
        if status != "OK" or not messages[0]:
            print("✅ No new messages.")
            mail.logout()
            return

        for num in messages[0].split():
            status, data = mail.fetch(num, "(RFC822)")
            msg = email.message_from_bytes(data[0][1])
            
            # Get unique ID to prevent infinite loops
            message_id = msg.get("Message-ID", "")
            if message_id in processed_message_ids:
                continue # Skip if we already processed this exact email
            
            sender = decode_str(msg["From"])
            subject = decode_str(msg["Subject"])
            
            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        body = part.get_payload(decode=True).decode()
                        break
            else:
                body = msg.get_payload(decode=True).decode()
                
            full_text = f"{subject}\n\n{body}"
            
            # Mark as read in Gmail
            mail.store(num, '+FLAGS', '\\Seen')
            
            # Add to our local memory so it never processes again
            processed_message_ids.add(message_id)
            
            payload = {
                "sender": sender,
                "text": full_text,
                "channel": "email"
            }
            
            print(f"📨 Found NEW email from {sender}. Sending to ScamShield AI...")
            
            try:
                response = requests.post(DJANGO_WEBHOOK_URL, json=payload, timeout=5)
                
                if response.status_code == 200:
                    print(f"✅ ScamShield Response: {response.json()}")
                else:
                    print(f"❌ Django Error {response.status_code}: {response.text[:100]}")
                    
            except Exception as e:
                print(f"❌ Failed to connect to Django: {e}")
            
        mail.logout()
    except Exception as e:
        print(f"Error connecting to email: {e}")

if __name__ == "__main__":
    print("🛡️ ScamShield Auto-Interceptor Started...")
    print("Waiting for incoming emails...")
    while True:
        fetch_unread_emails()
        time.sleep(10)