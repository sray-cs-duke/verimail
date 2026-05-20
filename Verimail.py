import os
import re
import mimetypes
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup

def parse_email(file_path):
    try:
        # Read the email file
        with open(file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)

        # Extract email details
        subject = msg['subject']
        from_email = msg['from']
        body = msg.get_body(preferencelist=('plain')).get_content()
        attachments = []

        # Extract attachments
        for part in msg.iter_attachments():
            filename = part.get_filename()
            content_type = part.get_content_type()
            if filename:
                temp_dir = "temp_attachments"
                os.makedirs(temp_dir, exist_ok=True)
                file_path = os.path.join(temp_dir, filename)
                with open(file_path, 'wb') as attachment_file:
                    attachment_file.write(part.get_content())
                attachments.append({
                    'filename': filename,
                    'content_type': content_type,
                    'file_path': file_path
                })

        return {
            'subject': subject,
            'from_email': from_email,
            'body': body,
            'attachments': attachments
        }

    except Exception as e:
        print(f"Error parsing email: {e}")
        return None

def analyze_email_content(subject, body):
    suspicion_score = 0

    # Expanded list of suspicious phrases
    suspicious_phrases = [
        "urgent", "account will be deactivated", "verify your account",
        "click here", "free services", "your account has been compromised",
        "click this link", "password reset", "unauthorized access"
    ]
    for phrase in suspicious_phrases:
        if phrase in body.lower() or phrase in subject.lower():
            print(f"Suspicious phrase detected: {phrase}")
            suspicion_score += 20

    # Check for excessive uppercase words (shouting)
    if len(re.findall(r'\b[A-Z]{3,}\b', body)) > 5:
        print("Suspicious: Excessive use of uppercase words.")
        suspicion_score += 10

    return suspicion_score

def analyze_sender_email(from_email):
    suspicion_score = 0

    # Check if the email domain is generic or suspicious
    domain = from_email.split("@")[1]
    if domain in ["gmail.com", "yahoo.com", "hotmail.com"]:
        print(f"Suspicious email domain: {domain}")
        suspicion_score += 30
    elif "microsoft.com" not in domain:  # Replace with trusted domains
        print(f"Email domain mismatch: {domain} (expected 'microsoft.com')")
        suspicion_score += 40

    return suspicion_score

def analyze_links(body):
    suspicion_score = 0
    links = re.findall(r'(https?://\S+)', body)
    for link in links:
        print(f"Found link: {link}")
        parsed_url = urlparse(link)
        domain = parsed_url.netloc
        print(f"Domain extracted: {domain}")

        # Check for suspicious or untrusted domains
        if domain not in ["microsoft.com", "paypal.com", "amazon.com"]:  # Replace with trusted domains
            print(f"Suspicious domain detected: {domain}")
            suspicion_score += 30

    return suspicion_score

def analyze_attachments(attachments):
    suspicion_score = 0
    for attachment in attachments:
        filename = attachment['filename']
        content_type = attachment['content_type']
        file_path = attachment['file_path']

        print(f"Analyzing attachment: {filename} (Type: {content_type})")

        # Check for suspicious file types
        if content_type in ['application/x-msdownload', 'application/zip', 'application/octet-stream']:
            print(f"Suspicious attachment detected: {filename} (Type: {content_type})")
            suspicion_score += 40

        # Clean up the temporary file after inspection
        os.remove(file_path)

    return suspicion_score

def detect_fake_email(email_file):
    email_data = parse_email(email_file)
    if not email_data:
        print("Failed to parse email.")
        return

    print(f"Subject: {email_data['subject']}")
    print(f"From: {email_data['from_email']}")

    # Analyze email content
    content_score = analyze_email_content(email_data['subject'], email_data['body'])

    # Analyze sender email
    sender_score = analyze_sender_email(email_data['from_email'])

    # Analyze links in the email body
    link_score = analyze_links(email_data['body'])

    # Analyze attachments
    attachment_score = analyze_attachments(email_data['attachments'])

    # Calculate total suspicion score
    total_score = content_score + sender_score + link_score + attachment_score
    print(f"\nTotal Suspicion Score: {total_score}/100")

    # Classify the email
    if total_score >= 70:
        print("This email is likely FAKE.")
    elif total_score >= 40:
        print("This email is SUSPICIOUS.")
    else:
        print("This email is SAFE.")

if __name__ == "__main__":
    print("Welcome to the Fake Email Detection Tool")
    print("1. Enter the path to the email file (.eml)")
    print("2. Enter email content manually")
    print("3. Exit")

    choice = input("Choose an option (1/2/3): ")

    if choice == "1":
        email_file = input("Enter the path to your .eml file: ")
        detect_fake_email(email_file)
    elif choice == "2":
        subject = input("Enter the email subject: ")
        from_email = input("Enter the sender's email address: ")
        body = input("Enter the email body: ")

        print(f"Subject: {subject}")
        print(f"From: {from_email}")

        # Analyze the input
        content_score = analyze_email_content(subject, body)
        sender_score = analyze_sender_email(from_email)
        link_score = analyze_links(body)

        total_score = content_score + sender_score + link_score
        print(f"\nTotal Suspicion Score: {total_score}/100")

        if total_score >= 70:
            print("This email is likely FAKE.")
        elif total_score >= 40:
            print("This email is SUSPICIOUS.")
        else:
            print("This email is SAFE.")
    elif choice == "3":
        print("Exiting the tool. Goodbye!")
    else:
        print("Invalid option. Please restart the tool.")
