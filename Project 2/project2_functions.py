import smtplib
import imaplib
import email
import os
import base64
import time
import struct

from datetime import datetime
from dateutil import parser

from email.MIMEText import MIMEText
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding, serialization, asymmetric
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC

#constants
ALICE_ADDR = "alice.crypto.project@gmail.com"
ALICE_KEYSTORE_FILENAME = "keystore_alice.txt"
BOB_ADDR = "bob.crypto.project@gmail.com"
BOB_KEYSTORE_FILENAME = "keystore_bob.txt"
PASSWORD = "cryptography"
SUBJECT_PREFIX = "Crypto:"
TTL = 5

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

	#Fri, 04 Dec 2015 10:16:34 -0800 (PST)
	parenIndex = email_message['Date'].index('(')
	timezone = email_message['Date'][parenIndex-6:parenIndex-1]
	#date_object = datetime.strptime(email_message['Date'], '%a, %d %b %Y %H:%M:%S ' + timezone + ' (%Z)')
	date_object = parser.parse(email_message['Date'])
	
	# print (int(time.mktime(date_object.timetuple())))

	return {
		'to': email_message['To'],
		'from': email.utils.parseaddr(email_message['From'])[1],
		'subject': email_message['Subject'],
		'body': base64.b64decode(email_message.get_payload(None, True)),
		'date': email_message['Date']
	}


def encryptRSA(public_key, message):
	ciphertext = public_key.encrypt(
		message,
		asymmetric.padding.OAEP(
			mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA1()),
			algorithm=hashes.SHA1(),
			label=None
		)
	)
	return ciphertext


def decryptRSA(private_key, ciphertext):
	plaintext = private_key.decrypt(
		ciphertext,
		asymmetric.padding.OAEP(
			mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA1()),
			algorithm=hashes.SHA1(),
			label=None
		)
	)
	return plaintext


def loadPrivateKeyRSA(keystore_filename):
	if os.path.exists(keystore_filename):
		keystore = open(keystore_filename, "r+")
	else:
		keystore = open(keystore_filename, "w+")

	pem_private_key = ""
	key_begins = False
	for line in keystore:
		if "-----BEGIN PRIVATE KEY-----" in line:
			key_begins = True

		if key_begins:
			pem_private_key += line

		if "-----END PRIVATE KEY-----" in line:
			key_begins = False

	if pem_private_key:
		private_key = serialization.load_pem_private_key(
			pem_private_key, 
			password=None,
			backend=default_backend()
		)
	else:
		private_key = asymmetric.rsa.generate_private_key(
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


def loadSharedKey(keystore_filename):
	keystore = open(keystore_filename, "r+")

	encoded_key = ""
	for line in keystore:
		if "shared_key: " in line:
			encoded_key = line[12:]

	if encoded_key:
		shared_key = base64.b64decode(encoded_key)
	else:
		shared_key = ""

	keystore.close()

	return shared_key


def storeSharedKey(keystore_filename, shared_key=os.urandom(32)):
	keystore = open(keystore_filename, "a")
	encoded_key = base64.b64encode(shared_key)
	keystore.write("shared_key: " + encoded_key + "\n")
	return shared_key
	

def encryptThenMac(data, key):
	#set up keys, current timestamp and initialization vector
	encryptKey = key[16:]
	signKey = key[:16]
	curTime = int(time.time())
	iv = os.urandom(16)
	
	#pad the data and encrypt using AES in CBC mode
	padder = padding.PKCS7(algorithms.AES.block_size).padder()
	paddedData = padder.update(data) + padder.finalize()
	encryptor = Cipher(algorithms.AES(encryptKey), modes.CBC(iv), default_backend()).encryptor()
	cipher = encryptor.update(paddedData) + encryptor.finalize()
	
	#get the HMAC using SHA256 of the combined parts and return everything combined
	parts = (b"\x80" + struct.pack(">Q", curTime) + iv + cipher)
	hasher = HMAC(signKey, hashes.SHA256(), backend=default_backend())
	hasher.update(parts)
	hmac = hasher.finalize()
	return base64.urlsafe_b64encode(parts + hmac)


def verifyThenDecrypt(cipher, emailTime, key):
	encryptKey = key[16:]
	signKey = key[:16]
	data = base64.urlsafe_b64decode(cipher)

	#verify timestamp to prevent replay
	timestamp, = struct.unpack(">Q", data[1:9])
	if timestamp + TTL < emailTime:
		raise InvalidTime

	#verify HMAC
	hasher = HMAC(signKey, hashes.SHA256(), backend=default_backend())
	hasher.update(data[:-32])
	try:
		hasher.verify(data[-32:])
	except InvalidSignature:
		raise InvalidSignature

	#decrypt cipher text
	iv = data[9:25]
	ciphertext = data[25:-32]
	decryptor = Cipher(algorithms.AES(encryptKey), modes.CBC(iv), default_backend()).decryptor()
	paddedPlaintext = decryptor.update(ciphertext)
	paddedPlaintext += decryptor.finalize()
	unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
	plaintext = unpadder.update(paddedPlaintext)
	plaintext += unpadder.finalize()

	return plaintext
