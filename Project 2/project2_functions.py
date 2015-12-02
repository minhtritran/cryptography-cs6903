import smtplib
import imaplib
import email

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

#constants
ALICE_ADDR = "alice.crypto.project@gmail.com"
BOB_ADDR = "bob.crypto.project@gmail.com"
PASSWORD = "cryptography"

def sendMail(from_addr, to_addr, subject, body):
	message = """\From: %s\nTo: %s\nSubject: %s\n\n%s
	""" % (from_addr, to_addr, subject, body)

	try:
		server = smtplib.SMTP('smtp.gmail.com', 587)
		server.ehlo()
		server.starttls()
		server.login(from_addr, PASSWORD)
		server.sendmail(from_addr, to_addr, message)
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
		'body': email_message.get_payload().strip()
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