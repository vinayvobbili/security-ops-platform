import base64
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import msal


def get_oauth2_access_token(client_id, client_secret, tenant_id, scope):
    authority = f"https://login.microsoftonline.com/{tenant_id}"
    app = msal.ConfidentialClientApplication(
        client_id,
        authority=authority,
        client_credential=client_secret,
    )
    result = app.acquire_token_for_client(scopes=[scope])
    if "access_token" in result:
        return result["access_token"]
    else:
        raise Exception(f"Could not obtain access token: {result}")


def send_office365_email_oauth2(sender_email, recipient_email, subject, body, cc_recipients=None, access_token=None):
    try:
        message = MIMEMultipart()
        message["From"] = sender_email
        message["To"] = recipient_email
        message["Subject"] = subject
        if cc_recipients:
            message["Cc"] = ", ".join(cc_recipients)
            all_recipients = [recipient_email] + cc_recipients
        else:
            all_recipients = [recipient_email]
        message.attach(MIMEText(body, "plain"))

        # Connect to Office 365 SMTP with OAuth2
        smtp_server = "smtp.office365.com"
        smtp_port = 587
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.ehlo()
        server.starttls()
        server.ehlo()

        # Prepare OAuth2 authentication string
        auth_string = f"user={sender_email}\x01auth=Bearer {access_token}\x01\x01"
        auth_bytes = base64.b64encode(auth_string.encode("utf-8")).decode("utf-8")
        server.docmd("AUTH", "XOAUTH2 " + auth_bytes)

        # Send email
        server.sendmail(
            sender_email,
            all_recipients,
            message.as_string()
        )
        server.quit()
        return True
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        return False


# Example usage
if __name__ == "__main__":
    # Azure AD app registration values (replace with your actual values)
    client_id = "YOUR_CLIENT_ID"
    client_secret = "YOUR_CLIENT_SECRET"
    tenant_id = "YOUR_TENANT_ID"
    scope = "https://outlook.office365.com/.default"

    sender = "user@company.com"
    recipient = "user@company.com"
    email_subject = "Test Email"
    email_body = "This is a test email sent from Python using Office 365 OAuth2!"
    cc_list = ["cc1@company.com", "cc2@company.com"]

    # Get OAuth2 access token
    try:
        access_token = get_oauth2_access_token(client_id, client_secret, tenant_id, scope)
    except Exception as e:
        print(f"Failed to get access token: {e}")
        access_token = None

    if access_token:
        success = send_office365_email_oauth2(
            sender_email=sender,
            recipient_email=recipient,
            subject=email_subject,
            body=email_body,
            cc_recipients=cc_list,
            access_token=access_token
        )
        if success:
            print("Email sent successfully.")
        else:
            print("Failed to send email.")
    else:
        print("No access token, cannot send email.")
