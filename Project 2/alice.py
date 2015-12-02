from project2_functions import *

# test code for sending mail
test_subject = "Crypto"
print "Enter email body: "
test_body = raw_input()

private_key = rsa.generate_private_key(
	public_exponent=65537,
	key_size=2048,
	backend=default_backend()
)
public_key = private_key.public_key()

ciphertext = encryptRSA(public_key, test_body)
# sendMail(ALICE_ADDR, BOB_ADDR, test_subject, ciphertext)

# test code for reading mail
# data = readMail(BOB_ADDR)
# decryptRSA(private_key, data['body'])