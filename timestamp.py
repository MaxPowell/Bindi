#!/usr/bin/python3.6

import rfc3161ng #timestamp
import sys


if (len(sys.argv) < 2):
	print ("Usage: timestamp.py [path_file_to_timestamp]")
	exit(1)

path = sys.argv[1]

# Open file
with open(path, "rb") as f:
	filedata = f.read()

# Timestamp file
print ("Connecting to TSA...")
tsa_cert_path = "/home/ubuntu/Desktop/certificates/tsa/tsa.crt" # Trusted timestamp cert
certificate = open(tsa_cert_path, 'rb').read()
rt = rfc3161ng.RemoteTimestamper('https://freetsa.org/tsr', certificate=certificate, hashname="sha256")
timestamp_data = rt.timestamp(data=filedata)

with open("timestamp.tst", "wb") as f_out:
	f_out.write(timestamp_data)

print("File has been securely timestamped")
