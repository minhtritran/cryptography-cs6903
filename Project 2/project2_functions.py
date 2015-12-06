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

# constants
PASSWORD = "cryptography"
SUBJECT_PREFIX = "Crypto:"
TTL = 5

# handle user input
def handleCommands(my_addr, my_keystore, other_addr):
	print "Enter command:"
	print "\t1: Request connection"
	print "\t2: Send message"
	print "\t3: Read most recent message"
	print "\t4: Show conversation history"
	print "\t5: Close connection"

	command = raw_input()

	# request a connection to the other party
	if command is "1":
		if connect(my_addr, my_keystore, other_addr):
			print "Successfully connected"

	# send a message to the other party
	elif command is "2":
		shared_key = connect(my_addr, my_keystore, other_addr)
		if shared_key:
			print "Enter your message:"
			body = raw_input()
			ciphertext = encryptThenMac(body, shared_key)
			sendMail(my_addr, other_addr, SUBJECT_PREFIX + "conversation", ciphertext)
	
	# read the most recent message from the other party
	elif command is "3":
		shared_key = connect(my_addr, my_keystore, other_addr)
		if shared_key:
			data = readRecentMail(my_addr)
			if SUBJECT_PREFIX + 'conversation' in data['subject']:
				message = verifyThenDecrypt(data['body'], data['timestamp'], shared_key)
				print "Date: " + data['date']
				print "From: " + data['from']
				print "Subject: " + data['subject']
				print "Message: " + message
			else:
				print "No valid message"

	# show the conversation history between you and the other party
	elif command is "4":
		shared_key = connect(my_addr, my_keystore, other_addr)
		if shared_key:
			displayConversation(my_addr, other_addr, shared_key)

	# close connection
	elif command is "5":
		shared_key = connect(my_addr, my_keystore, other_addr)
		if shared_key:
			ciphertext = encryptThenMac(shared_key, shared_key)
			sendMail(my_addr, other_addr, SUBJECT_PREFIX + "close", ciphertext)
			os.remove(my_keystore)
			print "Closed connection"
	
	else:
		print "Invalid command"


# request connection to the other email address
# returns the shared key if connection is established
# returns false otherwise
# connection is done in two steps:
#	step 1: party 1 sends their public key to party 2
#	step 2: party 2 receives it, and then sends a shared key to party 1
def connect(my_addr, my_keystore_filename, other_addr):
	data = readRecentMail(my_addr)

	shared_key = loadSharedKey(my_keystore_filename)
	if shared_key:
		# close connection if other party sent a 'close' message and if it matches our shared key
		# else, return the stored shared key
		if SUBJECT_PREFIX + "close" in data['subject']:
			message = verifyThenDecrypt(data['body'], data['timestamp'], shared_key)
			if message == shared_key:
				os.remove(my_keystore_filename)
				print "The other party closed the connection"
				return False
			else:
				return shared_key
		else:
			return shared_key

	# retrieve shared key
	private_key = loadPrivateKeyRSA(my_keystore_filename, False)
	if private_key and SUBJECT_PREFIX + "shared_key" in data['subject']:
		shared_key = decryptRSA(private_key, data['body'])
		storeSharedKey(my_keystore_filename, shared_key)
		return shared_key

	# send shared key
	elif SUBJECT_PREFIX + "pk" in data['subject']:
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
		print "No connection was established yet.  Connection request has been sent."

	return False


# send email
def sendMail(from_addr, to_addr, subject, body):
	msg = MIMEText(base64.b64encode(body))
	msg['Subject'] = subject
	msg['From'] = from_addr
	msg['To'] = to_addr

	try:
		server = smtplib.SMTP('smtp.gmail.com', 587)
		server.ehlo()
		server.starttls()
		server.login(from_addr, PASSWORD)
		server.sendmail(from_addr, to_addr, msg.as_string())
		server.close()
		print "Successfully sent mail"
	except:
		print "Failed to send mail"


# fetch the email given the IMAP mail object and the email's uid
def fetchMailByUID(mail, uid):
	result, data = mail.uid('fetch', uid, '(RFC822)')
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


# return most recent mail in inbox
def readRecentMail(addr):
	mail = imaplib.IMAP4_SSL('imap.gmail.com')
	mail.login(addr, PASSWORD)
	
	mail.list()
	mail.select("inbox")
	result, data = mail.uid('search', None, "ALL")

	if not data[0]:
		return {'to': "", 'from': "", 'subject': "", 'body': "", 'date': ""}

	latest_email_uid = data[0].split()[-1]
	
	return fetchMailByUID(mail, latest_email_uid)


# display conversation between two given parties using the given key
def displayConversation(my_addr, other_addr, shared_key):
	mail = imaplib.IMAP4_SSL('imap.gmail.com')
	mail.login(my_addr, PASSWORD)
	
	conversation = []

	# get all relevant emails from inbox
	mail.select("inbox")
	result, data = mail.uid('search', None, "ALL")
	for email_num in list(reversed(data[0].split())):
		email = fetchMailByUID(mail, email_num)

		if SUBJECT_PREFIX + "pk" in email['subject'] or SUBJECT_PREFIX + "shared_key" in email['subject']:
			break

		if email['to'] == my_addr and email['from'] == other_addr and SUBJECT_PREFIX + "conversation" in email['subject']:
			conversation.append(email)

	# get all relevant emails from 'sent'
	mail.select("[Gmail]/Sent Mail")
	result, data = mail.uid('search', None, "ALL")
	for email_num in list(reversed(data[0].split())):
		email = fetchMailByUID(mail, email_num)

		if SUBJECT_PREFIX + "pk" in email['subject'] or SUBJECT_PREFIX + "shared_key" in email['subject']:
			break

		if email['to'] == other_addr and email['from'] == my_addr and SUBJECT_PREFIX + "conversation" in email['subject']:
			conversation.append(email)

	# sort emails by timestamp
	conversation.sort(key = lambda x: x['timestamp'], reverse=False)
	
	# decrypt and display conversation
	for item in conversation:
		message = verifyThenDecrypt(item['body'], item['timestamp'], shared_key)
		print item['from'] + ":\t" + message


# encrypt the given message using the given RSA public key and return the ciphertext
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


# encrypt the given ciphertext using the given RSA private key and return the message
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


# given a keystore file, return the RSA private key
# if it doesn't exist and auto_generate flag is set to true, create one and return it
# if false, return a blank string
def loadPrivateKeyRSA(keystore_filename, auto_generate=True):
	# open file
	if os.path.exists(keystore_filename):
		keystore = open(keystore_filename, "r+")
	else:
		keystore = open(keystore_filename, "w+")

	# read file line by line to get the PEM-formatted private key
	pem_private_key = ""
	key_begins = False
	for line in keystore:
		if "-----BEGIN PRIVATE KEY-----" in line:
			key_begins = True

		if key_begins:
			pem_private_key += line

		if "-----END PRIVATE KEY-----" in line:
			key_begins = False

	# if it exists, decode the PEM-formatted private key
	if pem_private_key:
		private_key = serialization.load_pem_private_key(
			pem_private_key, 
			password=None,
			backend=default_backend()
		)
	else:
		# if it does not exist, generate one and also write it to file
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
		# if no keys exists and auto_generate is set to false, return a blank string
		else:
			private_key = ""

	keystore.close()

	return private_key


# given keystore file, return the stored shared key or a blank string if it doesn't exist
def loadSharedKey(keystore_filename):
	# open file
	if os.path.exists(keystore_filename):
		keystore = open(keystore_filename, "r+")
	else:
		return ""

	# read file line by line to find the encoded shared key
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


# store (put) the given shared key into the keystore file
# if none provided, auto generate one
def storeSharedKey(keystore_filename, shared_key=os.urandom(32)):
	# open file
	keystore = open(keystore_filename, "a")
	
	# write key to keystore and denote it with the header "shared key: "
	encoded_key = base64.b64encode(shared_key)
	keystore.write("shared_key: " + encoded_key + "\n")

	keystore.close()	
	return shared_key
	

# encrypt and tag the given data with the given key
# uses AES/CBC for encryption and HMAC/SHA256 for tagging
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


# verify and decrypt the given ciphertext with the given email time and key
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
