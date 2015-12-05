from project2_functions import *

my_addr = ALICE_ADDR
my_keystore = ALICE_KEYSTORE_FILENAME
other_addr = BOB_ADDR

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

	

# recieve RSA encryped shared key from bob
# data = readMail(my_addr)
# shared_key = decryptRSA(private_key, data['body'])
# storeSharedKey(my_keystore, shared_key)


# print "Enter email body: "
# test_body = raw_input()

# ciphertext = encryptRSA(public_key, test_body)

# key = os.urandom(32)
# cipher = encryptThenMac(test_body, key)
# print verifyThenDecrypt(cipher, 1, key)

# sendMail(my_addr, other_addr, test_subject, ciphertext)