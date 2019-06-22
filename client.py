#!/usr/bin/python3.6
import socket, ssl, os
import rfc3161ng #timestamp

root_certificate_path = "/home/ubuntu/Desktop/certificates/rootCA.pem"
client_certificate_path = "/home/ubuntu/Desktop/certificates/client_5caf1a66c851ddf9100f9182.pem"
client_certificate_key_path = "/home/ubuntu/Desktop/certificates/client_5caf1a66c851ddf9100f9182.key"

def send_file(file_path, file_size, name, socket):
	# Send file info
	file_info = "%s-%d" % (name, file_size)
	socket.send(file_info.encode())

	# Send file data
	i = 0
	with open(file_path, "rb") as in_file:
		while (i < file_size): 
			filedata = in_file.read(1024)
			ssock.send(filedata)
			i+=1024
	print("File '%s' sent" % (name))


# GET FILE INFO
file_path = "/home/ubuntu/Desktop/server/test.txt"
file_size = os.path.getsize(file_path)
filename = os.path.basename(file_path)
ts_path = "/home/ubuntu/Desktop/server/timestamp.tst"
ts_size = os.path.getsize(ts_path)
ts_name = os.path.basename(ts_path)

print("Loaded file: %s (%d B)" % (filename, file_size))
print("Loaded timestamp: %s (%d B)" % (ts_name, ts_size))

# CREATE SOCKET
host = '127.0.0.1'
port = 443
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.load_verify_locations(root_certificate_path) # CA to verify server
context.load_cert_chain(client_certificate_path, client_certificate_key_path) # cert of the client

# WRAP SOCKET
with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
	with context.wrap_socket(sock, server_hostname="Server") as ssock:
		#print(ssock.version())
		ssock.connect((host, port))

		# Send file and its signature
		send_file(file_path, file_size, filename, ssock)
		send_file(ts_path, ts_size, ts_name, ssock)



