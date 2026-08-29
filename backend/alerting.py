import smtplib
from email.mime.text import MIMEText

def send_email_alert(alert_obj):
    # Dummy implementation for now
    print(f"\n[{alert_obj['timestamp']}] --- EMAIL ALERT TRIGGERED ---")
    print(f"Severity: {alert_obj['severity']}")
    print(f"Type: {alert_obj['attack_type']}")
    print(f"Description: {alert_obj['description']}")
    print(f"-----------------------------------------\n")
