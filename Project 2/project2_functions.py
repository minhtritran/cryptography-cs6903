import smtplib
import imaplib
import email
import os
import base64

from email.MIMEText import MIMEText
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

#constants
ALICE_ADDR = "alice.crypto.project@gmail.com"
ALICE_KEYSTORE_FILENAME = "keystore_alice.txt"
BOB_ADDR = "bob.crypto.project@gmail.com"
BOB_KEYSTORE_FILENAME = "keystore_bob.txt"
PASSWORD = "cryptography"

def sendMail(from_addr, to_addr, subject, body):
	msg = MIMEText(base64.b64encode(body))
	msg['Subject'] = subject
	msg['From'] = from_addr
	msg['To'] = to_addr

	#message = """From: %s\nTo: %s\nSubject: %s\n\n%s""" % (from_addr, to_addr, subject, body)

	try:
		server = smtplib.SMTP('smtp.gmail.com', 587)
		server.ehlo()
		server.starttls()
		server.login(from_addr, PASSWORD)
		server.sendmail(from_addr, to_addr, msg.as_string())
		server.close()
		print "successfully send mail"
	except:
		print "failed to send mail"


# return most recent mail
def readMail(addr):
	mail = imaplib.IMAP4_SSL('imap.gmail.com')
	mail.login(addr, PASSWORD)
	mail.list()
	mail.select("inbox")

	result, data = mail.uid('search', None, "ALL")

	latest_email_uid = data[0].split()[-1]
	result, data = mail.uid('fetch', latest_email_uid, '(RFC822)')
	raw_email = data[0][1]

	email_message = email.message_from_string(raw_email)

	return {
		'to': email_message['To'],
		'from': email.utils.parseaddr(email_message['From'])[1],
		'subject': email_message['Subject'],
		'body': base64.b64decode(email_message.get_payload(None, True))
	}


def encryptRSA(public_key, message):
	ciphertext = public_key.encrypt(
		message,
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA1()),
			algorithm=hashes.SHA1(),
			label=None
		)
	)
	return ciphertext


def decryptRSA(private_key, ciphertext):
	plaintext = private_key.decrypt(
		ciphertext,
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA1()),
			algorithm=hashes.SHA1(),
			label=None
		)
	)
	return plaintext


def loadPrivateKeyRSA(keystore_filename):
	if os.path.exists(keystore_filename):
		keystore = open(keystore_filename, "rb")
	else:
		keystore = open(keystore_filename, "w+")

	pem_private_key = keystore.read()
		
	if pem_private_key:
		private_key = serialization.load_pem_private_key(
			pem_private_key, 
			password=None,
			backend=default_backend()
		)
	else:
		private_key = rsa.generate_private_key(
			public_exponent=65537,
			key_size=2048,
			backend=default_backend()
		)
		keystore.write(private_key.private_bytes(
			encoding=serialization.Encoding.PEM, 
			format=serialization.PrivateFormat.PKCS8, 
			encryption_algorithm=serialization.NoEncryption()
		))

	keystore.close()

	return private_key
