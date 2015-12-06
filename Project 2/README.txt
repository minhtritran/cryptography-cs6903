Cryptography Project 2
CS-UY-4783
Minhtri Tran and Wilson Li

Summary:
A project that demonstrates cryptography concepts via 2-party communications over email.

Platform: Linux (Ubuntu)
Programming Language: Python 2.7.x
Libraries used: cryptography and dateutil

Installation Guide:
1. Install Python (2.7.x) and pip
2. Install cryptography
	apt-get install build-essential libssl-dev libffi-dev python-dev
	pip install cryptography
3. Install dateutil
	pip install python-dateutil

Testing Guide:
Run alice.py if you want to input commands as Alice
Run bob.py if you want to input commands as Bob
Refer to our powerpoint/pdf presentation's screenshots for additional reference

You can access Alice and Bob's gmail accounts with the following credentials
	Alice's gmail username: alice.crypto.project@gmail.com
	Alice's gmail password: cryptography
	Bob's gmail username: bob.crypto.project@gmail.com
	Bob's gmail password: cryptography

In case of bugs, do the following
	Delete the two auto-generated files - keystore_alice.txt and keystore_bob.txt
	Delete all emails in Inbox for Alice and Bob using gmail


