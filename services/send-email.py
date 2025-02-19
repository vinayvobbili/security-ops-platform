import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional, List


def send_office365_email(
        sender_email: str,
        sender_password: str,
        recipient_email: str,
        subject: str,
        body: str,
        cc_recipients: Optional[List[str]] = None
) -> bool:
    """
    Send an email using Office 365 SMTP.

    Args:
        sender_email: Your Acme email address
        sender_password: Your Office 365 password
        recipient_email: The email address of the recipient
        subject: The subject line of the email
        body: The body content of the email
        cc_recipients: Optional list of CC recipients

    Returns:
        bool: True if email was sent successfully, False otherwise
    """
    # Office 365 SMTP settings
    SMTP_SERVER = "smtp.office365.com"
    SMTP_PORT = 587

    try:
        # Create the email message
        message = MIMEMultipart()
        message["From"] = sender_email
        message["To"] = recipient_email
        message["Subject"] = subject

        # Add CC recipients if provided
        if cc_recipients:
            message["Cc"] = ", ".join(cc_recipients)

        # Add body to email
        message.attach(MIMEText(body, "plain"))

        # Create SMTP session
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            # Start TLS for security
            server.starttls()

            # Login to the server
            server.login(sender_email, sender_password)

            # Get all recipients
            all_recipients = [recipient_email]
            if cc_recipients:
                all_recipients.extend(cc_recipients)

            # Send email
            server.sendmail(
                sender_email,
                all_recipients,
                message.as_string()
            )

        return True

    except Exception as e:
        print(f"Error sending email: {str(e)}")
        return False


# Example usage
if __name__ == "__main__":
    # Acme Office 365 settings
    sender = "user@company.com"
    password = ""  # Your actual Office 365 password
    recipient = "user@company.com"
    email_subject = "Test Email"
    email_body = "This is a test email sent from Python using Office 365!"
    cc_list = ["cc1@company.com", "cc2@company.com"]  # Optional CC recipients

    # Send the email
    success = send_office365_email(
        sender_email=sender,
        sender_password=password,
        recipient_email=recipient,
        subject=email_subject,
        body=email_body,
        cc_recipients=cc_list
    )

    if success:
        print("Email sent successfully!")
    else:
        print("Failed to send email.")
