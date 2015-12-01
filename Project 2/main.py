import smtplib
import imaplib
import email

#constants
ALICE_ADDR = "alice.crypto.project@gmail.com"
BOB_ADDR = "bob.crypto.project@gmail.com"
PASSWORD = "cryptography"

def sendMail(from_addr, to_addr, subject, body):
	message = """\From: %s\nTo: %s\nSubject: %s\n\n%s
	""" % (from_addr, to_addr, subject, body)

	try:
		server = smtplib.SMTP('smtp.gmail.com', 587)
		server.ehlo()
		server.starttls()
		server.login(from_addr, PASSWORD)
		server.sendmail(from_addr, to_addr, message)
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

	latest_email_uid = data[0].split()[-1]
	result, data = mail.uid('fetch', latest_email_uid, '(RFC822)')
	raw_email = data[0][1]

	email_message = email.message_from_string(raw_email)

	return {
		'to': email_message['To'],
		'from': email.utils.parseaddr(email_message['From'])[1],
		'subject': email_message['Subject'],
		'body': email_message.get_payload().strip()
	}


# test code for sending mail
test_subject = "Crypto"
print "Enter email body: "
test_body = raw_input()
sendMail(ALICE_ADDR, BOB_ADDR, test_subject, test_body)

# test code for reading mail
# data = readMail(BOB_ADDR)
# print data['body']