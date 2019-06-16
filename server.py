#!/usr/bin/python3.6
import socket, ssl
from OpenSSL import crypto
import pymongo # Module for mongo
import binascii # Bin2Hex
import pprint # Print JSON documents
import datetime # Get system datetime
import base64
from Crypto import Random
from Crypto.Cipher import AES
import hashlib

# Check client identity and receive file
def deal_with_client(conn):
	print("Connection accepted")

	# Check user identity
	cert = conn.getpeercert(binary_form=True)
	cert_parsed = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)
	client = cert_parsed.get_subject().commonName
	print("Successfully authenticated client: %s" % (client))

	# Receive 2 files: the file and its signature
	filename = receive_file(conn)
	ts_name = receive_file(conn)
	
	# Upload files to mongo
	upload_mongo(client, filename, ts_name)


# Receive a file from a connection
def receive_file(conn):
	data = conn.recv(1024) # file info will be sent first -> packet = [name]-[size]
	file_info = data.decode()
	filename, size = file_info.split('-')
	size = int(size)

	print ("Processing %s file (%d B)" % (filename, size))
	with open(filename, 'wb') as f:
		i = 0 # number of bytes already written
		while (i < size):
			filedata = conn.recv(1024)
			f.write(filedata)
			i+=1024
	print ("File '%s' has been received" % (filename))
	return filename


# Upload data to client's mongo account
def upload_mongo(commonName, filename, ts_name):
	user = commonName.split('_')[1]
	
	# Connect to mongo
	client = pymongo.MongoClient(username=user, password="password", authSource=commonName, ssl=True, ssl_ca_certs=path_CA_cert, ssl_certfile=path_server_cert, ssl_keyfile=path_server_cert, ssl_match_hostname=False)
	
	# Get collection of user
	collection = client.get_database(name=commonName).get_collection("files")
	
	
	# Read files
	with open(filename, 'rb') as f:
		filedata = f.read()
	with open(ts_name, 'rb') as f:
		ts_data = f.read()

	# Process data
	cipher = AESCipher(AES_key)
	enc_data = cipher.encrypt(filedata) # encrypt data

	print ("Encrypted data: %s" % (enc_data))
	hex_data = binascii.hexlify(enc_data) # encrypted hex data 
	hex_ts = binascii.hexlify(ts_data)

	# JSON document
	document = { 	
				"filename": filename, 
				"data": hex_data,
				"timestamp_tst": hex_ts,
				"uploadTimestamp": str(datetime.datetime.utcnow()) }

	# Inserting data to DB
	print("Uploading data to database...")
	inserted_id = collection.insert_one(document).inserted_id
	print("File %s has been uploaded to database with ID %s" % (filename, inserted_id))
	


class AESCipher:

	def __init__( self, key ):
		self.key = hashlib.sha256(key.encode('utf-8')).digest()

	def encrypt( self, raw ):
		raw = AESCipher.pad(raw)
		#raw = pad(raw)
		iv = Random.new().read( AES.block_size )
		cipher = AES.new( self.key, AES.MODE_CBC, iv )
		print(raw)
		return base64.b64encode( iv + cipher.encrypt( raw ) )

	def decrypt( self, enc ):
		enc = base64.b64decode(enc)
		iv = enc[:16]
		cipher = AES.new(self.key, AES.MODE_CBC, iv )
		return unpad(cipher.decrypt( enc[16:] ))

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


####################################################################################

# AES parameters
BS = 16
AES_key = "mysecretpassword"

# Certificate parameters
path_CA_cert = "/home/ubuntu/Desktop/certificates/rootCA.pem"
path_server_cert = "/home/ubuntu/Desktop/certificates/server.pem"
path_server_key = "/home/ubuntu/Desktop/certificates/server.key"


# Setup ssl parameters
context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH,cafile=path_CA_cert)
context.verify_mode = ssl.CERT_REQUIRED
context.load_cert_chain(path_server_cert, path_server_key) # server certificate and key
context.load_verify_locations(path_CA_cert) # CA to verify client

print ("Starting server...")
with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
	sock.bind(('127.0.0.1', 443))
	sock.listen(5) # start listening
	print ("Server listening...")
	while True:
		new_socket, addr = sock.accept() # accept connection
		conn = context.wrap_socket(new_socket, server_side=True)
		try:
			# Deal with client
			deal_with_client(conn)

		finally:
			print("Closing connection...")
			conn.shutdown(socket.SHUT_RDWR)
			conn.close()
