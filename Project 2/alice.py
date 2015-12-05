from project2_functions import *

# send public key to bob
private_key = loadPrivateKeyRSA(ALICE_KEYSTORE_FILENAME)
public_key = private_key.public_key()

public_key_str = public_key.public_bytes(
	encoding=serialization.Encoding.PEM, 
	format=serialization.PublicFormat.SubjectPublicKeyInfo
)
sendMail(ALICE_ADDR, BOB_ADDR, SUBJECT_PREFIX + "pk", public_key_str)

# recieve RSA encryped shared key from bob
# data = readMail(ALICE_ADDR)
# shared_key = decryptRSA(private_key, data['body'])
# storeSharedKey(ALICE_KEYSTORE_FILENAME, shared_key)


# print "Enter email body: "
# test_body = raw_input()

# ciphertext = encryptRSA(public_key, test_body)

# key = os.urandom(32)
# cipher = encryptThenMac(test_body, key)
# print verifyThenDecrypt(cipher, 1, key)

# sendMail(ALICE_ADDR, BOB_ADDR, test_subject, ciphertext)