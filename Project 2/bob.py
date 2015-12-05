from project2_functions import *

# Use alice's public key to send a shared key
data = readMail(BOB_ADDR)
public_key = serialization.load_pem_public_key(data['body'], backend=default_backend())

shared_key = loadSharedKey(BOB_KEYSTORE_FILENAME)
if not shared_key:
	shared_key = storeSharedKey(BOB_KEYSTORE_FILENAME)

ciphertext = encryptRSA(public_key, shared_key)
sendMail(BOB_ADDR, ALICE_ADDR, SUBJECT_PREFIX + "shared_key", ciphertext)



# # Using Alice's private key as a test
# private_key = loadPrivateKeyRSA(ALICE_KEYSTORE_FILENAME)

# data = readMail(BOB_ADDR)
# #print data

# print decryptRSA(private_key, data['body'])