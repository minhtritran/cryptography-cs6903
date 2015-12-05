from project2_functions import *

my_addr = BOB_ADDR
my_keystore = BOB_KEYSTORE_FILENAME
other_addr = ALICE_ADDR

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
		sendMail(my_addr, other_addr, SUBJECT_PREFIX + "test", ciphertext)
elif command is "3":
	shared_key = connect(my_addr, my_keystore, other_addr)
	if not shared_key:
		print "No connection was established yet.  Connection request sent."
	else:
		data = readMail(my_addr)
		if 'test' in data['subject']:
			message = verifyThenDecrypt(data['body'], 1, shared_key)
			print message
		else:
			print "No valid message"
elif command is "4":
	print "close connection"
else:
	print "Invalid command"

# # Use alice's public key to send a shared key
# data = readMail(BOB_ADDR)
# public_key = serialization.load_pem_public_key(data['body'], backend=default_backend())

# shared_key = loadSharedKey(BOB_KEYSTORE_FILENAME)
# if not shared_key:
# 	shared_key = storeSharedKey(BOB_KEYSTORE_FILENAME)

# ciphertext = encryptRSA(public_key, shared_key)
# sendMail(BOB_ADDR, ALICE_ADDR, SUBJECT_PREFIX + "shared_key", ciphertext)



# # Using Alice's private key as a test
# private_key = loadPrivateKeyRSA(ALICE_KEYSTORE_FILENAME)

# data = readMail(BOB_ADDR)
# #print data

# print decryptRSA(private_key, data['body'])