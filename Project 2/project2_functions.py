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
PASSWORD = "cryptography"
SUBJECT_PREFIX = "Crypto:"
TTL = 5

def handleCommands(my_addr, my_keystore, other_addr):
	print "Enter command:"
	print "\t1: Request connection"
	print "\t2: Send message"
	print "\t3: Read most recent message"
	print "\t4: Close connection"

	command = raw_input()

	if command is "1":
		if connect(my_addr, my_keystore, other_addr):
			print "Successfully connected"
		else:
			print "Connection request sent"
	elif command is "2":
		shared_key = connect(my_addr, my_keystore, other_addr)
		if not shared_key:
			print "No connection was established yet.  Connection request sent."
		else:
			print "Enter your message:"
			body = raw_input()
			ciphertext = encryptThenMac(body, shared_key)
			sendMail(my_addr, other_addr, SUBJECT_PREFIX + "conversation", ciphertext)
	elif command is "3":
		shared_key = connect(my_addr, my_keystore, other_addr)
		if not shared_key:
			print "No connection was established yet.  Connection request sent."
		else:
			data = readMail(my_addr)
			if SUBJECT_PREFIX + 'conversation' in data['subject']:
				message = verifyThenDecrypt(data['body'], data['timestamp'], shared_key)
				print "Date: " + data['date']
				print "From: " + data['from']
				print "Subject: " + data['subject']
				print "Message: " + message
			else:
				print "No valid message"
	elif command is "4":
		print "close connection"
	else:
		print "Invalid command"


def connect(my_addr, my_keystore_filename, other_addr):
	# if already connected
	shared_key = loadSharedKey(my_keystore_filename)
	if shared_key:
		return shared_key

	private_key = loadPrivateKeyRSA(my_keystore_filename, False)
	data = readMail(my_addr)

	# retrieve shared key
	if private_key and SUBJECT_PREFIX + "shared_key" in data['subject']:
		shared_key = decryptRSA(private_key, data['body'])
		storeSharedKey(my_keystore_filename, shared_key)
		return shared_key

	# send shared key
	if SUBJECT_PREFIX + "pk" in data['subject']:
		public_key = serialization.load_pem_public_key(data['body'], backend=default_backend())
		shared_key = loadSharedKey(my_keystore_filename)
		if not shared_key:
			shared_key = storeSharedKey(my_keystore_filename)
		ciphertext = encryptRSA(public_key, shared_key)
		sendMail(my_addr, other_addr, SUBJECT_PREFIX + "shared_key", ciphertext)
		return shared_key

	# send public key
	else:
		private_key = loadPrivateKeyRSA(my_keystore_filename)
		public_key = private_key.public_key()

		public_key_str = public_key.public_bytes(
			encoding=serialization.Encoding.PEM, 
			format=serialization.PublicFormat.SubjectPublicKeyInfo
		)
		sendMail(my_addr, other_addr, SUBJECT_PREFIX + "pk", public_key_str)

	return False


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

	if not data[0]:
		return {'to': "", 'from': "", 'subject': "", 'body': "", 'date': ""}

	latest_email_uid = data[0].split()[-1]
	result, data = mail.uid('fetch', latest_email_uid, '(RFC822)')
	raw_email = data[0][1]

	email_message = email.message_from_string(raw_email)

	#create timestamp field based on email datetime
	date_object = parser.parse(email_message['Date'])
	utc_time = date_object.replace(tzinfo=None) - date_object.utcoffset()
	timestamp = (utc_time - datetime(1970, 1, 1)).total_seconds()

	return {
		'to': email_message['To'],
		'from': email.utils.parseaddr(email_message['From'])[1],
		'subject': email_message['Subject'],
		'body': base64.b64decode(email_message.get_payload(None, True)),
		'date': email_message['Date'],
		'timestamp': int(timestamp)
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


def loadPrivateKeyRSA(keystore_filename, auto_generate=True):
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
		if auto_generate:
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
		else:
			private_key = ""

	keystore.close()

	return private_key


def loadSharedKey(keystore_filename):
	if os.path.exists(keystore_filename):
		keystore = open(keystore_filename, "r+")
	else:
		return ""

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

	keystore.close()	
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
