"""Sends one plain-text email through your SMTP server (STARTTLS on port 587 by default).
Only used for the optional emailed sign-in code. The app puts the sender in app.state.mailer, so tests can swap it."""
import smtplib, ssl
from email.message import EmailMessage


def make_mailer(s):
    def send(to, subject, body):
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = s.smtp_from, to, subject
        msg.set_content(body)
        with smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=15) as smtp:
            smtp.starttls(context=ssl.create_default_context())
            if s.smtp_username:
                smtp.login(s.smtp_username, s.smtp_password)
            smtp.send_message(msg)
    return send
