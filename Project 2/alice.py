from project2_functions import *

test_subject = "Crypto 2"
print "Enter email body: "
test_body = raw_input()

private_key = loadPrivateKeyRSA(ALICE_KEYSTORE_FILENAME)
public_key = private_key.public_key()

ciphertext = encryptRSA(public_key, test_body)

key = os.urandom(32)
cipher = encryptThenMac(test_body, key)
print verifyThenDecrypt(cipher, 1, key)

sendMail(ALICE_ADDR, BOB_ADDR, test_subject, ciphertext)