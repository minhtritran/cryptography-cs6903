from project2_functions import *

# Using Alice's private key as a test
private_key = loadPrivateKeyRSA(ALICE_KEYSTORE_FILENAME)

data = readMail(BOB_ADDR)

print decryptRSA(private_key, data['body'])