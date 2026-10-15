
# auto_interceptor.py

import os
import time
import imaplib
import email
import logging
import requests

from email.header import decode_header
from email.message import Message


# ---------------- CONFIGURATION ----------------

EMAIL_ACCOUNT = os.environ["GMAIL_ADDRESS"]
EMAIL_PASSWORD = os.environ["GMAIL_APP_PASSWORD"]
DJANGO_WEBHOOK_URL = os.environ["SCAMSHIELD_API_URL"]

POLL_INTERVAL = 30  # Check Gmail every 30 seconds
REQUEST_TIMEOUT = 20

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

# -----------------------------------------------


def decode_header_value(value):
    """Decode an email header safely."""
    if not value:
        return ""

    decoded_parts = decode_header(value)
    result = []

    for part, charset in decoded_parts:
        if isinstance(part, bytes):
            result.append(
                part.decode(charset or "utf-8", errors="replace")
            )
        else:
            result.append(part)

    return "".join(result)


def extract_text_body(msg: Message) -> str:
    """Extract readable plain-text content, excluding attachments."""
    parts = []

    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_maintype() == "multipart":
                continue

            if part.get_content_disposition() == "attachment":
                continue

            if part.get_content_type() != "text/plain":
                continue

            payload = part.get_payload(decode=True)
            if payload:
                charset = part.get_content_charset() or "utf-8"
                parts.append(
                    payload.decode(charset, errors="replace")
                )
    elif msg.get_content_type() == "text/plain":
        payload = msg.get_payload(decode=True)

        if payload:
            charset = msg.get_content_charset() or "utf-8"
            parts.append(
                payload.decode(charset, errors="replace")
            )

    return "\n".join(parts).strip()


def fetch_unread_emails():
    mail = None

    try:
        logging.info("Checking Gmail for unread messages...")

        mail = imaplib.IMAP4_SSL("imap.gmail.com", 993)
        mail.login(EMAIL_ACCOUNT, EMAIL_PASSWORD)

        status, _ = mail.select("INBOX")

        if status != "OK":
            raise RuntimeError("Could not select Gmail inbox")

        status, data = mail.search(None, "UNSEEN")

        if status != "OK":
            raise RuntimeError("Could not search Gmail inbox")

        message_numbers = data[0].split() if data and data[0] else []

        if not message_numbers:
            logging.info("No unread emails.")
            return

        # Oldest unread email first
        for number in message_numbers:
            try:
                status, fetched = mail.fetch(number, "(RFC822)")

                if status != "OK" or not fetched:
                    logging.warning(
                        "Could not fetch email %s", number.decode()
                    )
                    continue

                raw_email = next(
                    (
                        item[1]
                        for item in fetched
                        if isinstance(item, tuple)
                        and isinstance(item[1], bytes)
                    ),
                    None,
                )

                if raw_email is None:
                    logging.warning("Email content was unavailable.")
                    continue

                msg = email.message_from_bytes(raw_email)

                sender = decode_header_value(msg.get("From"))
                subject = decode_header_value(msg.get("Subject"))
                body = extract_text_body(msg)

                full_text = (
                    f"Subject: {subject}\n\n"
                    f"{body}"
                ).strip()

                if not full_text:
                    logging.warning(
                        "Skipping email without readable text."
                    )
                    continue

                payload = {
                    "sender": sender or "Unknown",
                    "text": full_text[:20000],
                    "channel": "email",
                }

                logging.info(
                    "Submitting email from %s for analysis.", sender
                )

                # If this fails, leave the email unread for a retry.
                response = requests.post(
                    DJANGO_WEBHOOK_URL,
                    json=payload,
                    timeout=REQUEST_TIMEOUT,
                )

                if response.status_code == 200:
                    logging.info(
                        "Email analyzed successfully by ScamShield."
                    )

                    # Mark as read only after successful submission.
                    mark_status, _ = mail.store(
                        number, "+FLAGS", "\\Seen"
                    )

                    if mark_status != "OK":
                        logging.warning(
                            "Could not mark the email as read."
                        )
                else:
                    logging.error(
                        "Django returned HTTP %s: %s",
                        response.status_code,
                        response.text[:300],
                    )

            except requests.RequestException as exc:
                logging.error("Could not reach Django: %s", exc)

            except Exception:
                logging.exception("Failed to process an email.")

    except Exception:
        logging.exception("Gmail connection or inbox check failed.")

    finally:
        if mail is not None:
            try:
                mail.logout()
            except Exception:
                pass


if __name__ == "__main__":
    logging.info("ScamShield Gmail interceptor started.")

    while True:
        fetch_unread_emails()
        time.sleep(POLL_INTERVAL)
