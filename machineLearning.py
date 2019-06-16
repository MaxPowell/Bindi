#!/usr/bin/python3.6
import pymongo
import pprint
import binascii
import rfc3161ng #timestamp
from Crypto import Random
from Crypto.Cipher import AES
import hashlib
import base64

class AESCipher:

	def __init__( self, key ):
		self.key = hashlib.sha256(key.encode('utf-8')).digest()

	def encrypt( self, raw ):
		raw = AESCipher.pad(raw)
		iv = Random.new().read( AES.block_size )
		cipher = AES.new( self.key, AES.MODE_CBC, iv )
		return base64.b64encode( iv + cipher.encrypt( raw ) )

	def decrypt( self, enc ):
		enc = base64.b64decode(enc)
		iv = enc[:16]
		cipher = AES.new(self.key, AES.MODE_CBC, iv )
		return AESCipher.unpad(cipher.decrypt( enc[16:] ))

	def pad( raw ):
		bytes_left = (BS - (len(raw) % BS)) 
		char = hex(bytes_left)
		return (raw + (char[-1:].encode()*bytes_left))

	def unpad( raw ):
		pad = raw[-1:]
		num_pad = int(pad.decode(), 16)
		padded = 1
		i=0
		while(i<num_pad-1):
			if raw[-num_pad+i:-num_pad+i+1]!=raw[-1:]:
				print("%s and %s are different" % (raw[-num_pad+i:-num_pad+i+1], raw[-1:]))
				padded=0
				break
			i+=1
		if padded:
			return (raw[0:-num_pad])	
		else:
			return raw

########################################

# AES parameters
BS = 16
AES_key = "mysecretpassword"


#########################
# Setting up connection #
#########################

print("Setting up connection...")

path_CA_cert="/home/ubuntu/Desktop/certificates/rootCA.pem"
path_client_cert="/home/ubuntu/Desktop/certificates/ml.pem"

# Connect to the database
client = pymongo.MongoClient(username="ml", password="password", ssl=True, ssl_ca_certs=path_CA_cert, ssl_certfile=path_client_cert, ssl_keyfile=path_client_cert, ssl_match_hostname=False)


##########################
# Retrieving client data #
##########################

print("Connecting to db...")
databases = client.list_database_names()
client_dbs = []
for i in databases:
	if "client_" in i:
		client_dbs.append(i)

print("Retrieving files...\n")
for db_name in client_dbs:
	collection = client.get_database(name=db_name).get_collection("files")
	for document in collection.find():
		# retrieve data from document
		filename = document.get('filename')
		uploadTime = document.get('uploadTimestamp')
		hex_data = document.get('data')
		hex_tst = document.get('timestamp_tst')

		# decode from hex
		enc_data = binascii.unhexlify(hex_data)
		tst = binascii.unhexlify(hex_tst)

		# decrypt data
		cipher = AESCipher(AES_key)
		data = cipher.decrypt(enc_data)
		
		# check timestamp
		tsa_cert_path = "/home/ubuntu/Desktop/certificates/tsa/tsa.crt"
		certificate = open(tsa_cert_path, 'rb').read()
		rt = rfc3161ng.RemoteTimestamper('https://freetsa.org/tsr', certificate=certificate, hashname="sha256")
		if(rt.check(tst, data)):
			print("Retrieved file: %s " % filename)
			print("Signature is correct")
			print("Creation timestamp: %s" % (rfc3161ng.get_timestamp(tst)))
			print("Upload time: %s" % (uploadTime))
			print("Data: ", data)
			print("\n")
		else:
			print("Signature is not correct for file: %s" % (filename))


		

