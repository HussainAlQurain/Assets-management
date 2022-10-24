from tokenize import String
import dotenv
import os
from cryptography.fernet import Fernet
import smtplib
import ssl


def sendMail():
    with open('key.key', 'rb') as f:
        key = f.readline()
        password = f.readline()

    token = Fernet(key)

    port = 587
    smtp_server = "smtp-mail.outlook.com"

    tmp = token.decrypt(password)
    sender_email = os.getenv('username')
    sender_password = tmp.decode('UTF-8')
    recipient = "rayleigh1423@gmail.com"

    message = """

    Subject: This is a test message

    Sent using Python."""

    SSL_context = ssl.create_default_context()

    with smtplib.SMTP(smtp_server, port) as server:

        server.starttls(context=SSL_context)

        server.login(sender_email, sender_password)

        server.sendmail(sender_email, recipient, message)

sendMail()