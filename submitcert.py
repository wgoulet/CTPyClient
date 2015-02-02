import os
import base64
import json
import urllib
import io
import sys
import requests
import struct
from OpenSSL import crypto
from curses.ascii import isprint
from pyasn1.codec.der import decoder as der_decoder
import pyasn1
import pyasn1_modules

def main(args):
    if len(args) < 1:
	print "Usage submitcert.py [filename(s) to certificate chain to submit]"
	sys.exit(1)
    fname = args[0]
    operation = 'ct/v1/add-chain'
    url = 'http://ct.api.venafi.com/{}'.format(operation)
    certlist = []

    for fname in args:
	# Read in cert file; if it is PEM formatted convert it
	# to DER first
	fhandle = io.BufferedReader(io.open(fname,'br'))
	pemflag = False
	b = fhandle.read(20)
	if not b:
	    print "File empty"
	else:
	    if("-----BEGIN" in b):
		pemflag = True
	b64str = ""
	dercert = ""

	if pemflag:
	    # Convert the PEM cert in memory to DER format, then
	    # base64 convert the result. This is safer than manually
	    # parsing PEM cert to remove PEM headers and line breaks
	    fhandle.seek(0)
	    certdata = fhandle.read() # read all data
	    certobj = crypto.load_certificate(crypto.FILETYPE_PEM,certdata)
	    dercert = crypto.dump_certificate(crypto.FILETYPE_ASN1,certobj)
	    # debug test
	    fhandle = io.open(".\derconv.cer","wb+")
	    fhandle.write(dercert)
	    #b64str = base64.b64encode(dercert)
        else:
	    fhandle.seek(0)
	    certdata = fhandle.read()
	    # confirm this is single DER encoded cert
	    try:
		dercert = crypto.load_certificate(crypto.FILETYPE_ASN1,certdata)
	    except:
		print "no der"

	b64str = base64.b64encode(dercert)
	certlist.append(b64str)

    payload = {'chain':certlist}
    headers = {'content-type':'application/json'}
    r = requests.post(url,data=json.dumps(payload),headers=headers)

    if r.status_code == 200:
	print "sent log"
	print r.text
    else:
	print r.status_code
	print r.text

def create_asn1cert(inbytes):
    # Create a RFC 5246 compliant ASN1Cert object, where the first 3 bytes
    # are the length of the cert object and remaining bytes contain the cert

    
    blen = len(inbytes)
    derlen = struct.pack(">I",blen)
    nbuf = derlen + inbytes
    return base64.b64encode(nbuf)

if __name__ == "__main__":
    main(sys.argv[1:])
