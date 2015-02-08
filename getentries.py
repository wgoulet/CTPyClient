import os
import base64
import json
import urllib
import io
import sys
import struct
import hashlib
from requests import Session, Request
from OpenSSL import crypto
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from curses.ascii import isprint
from pyasn1.codec.der import decoder as der_decoder
import pyasn1
import pyasn1_modules
import ecdsa
from ecdsa import SigningKey, VerifyingKey, NIST256p, BadSignatureError
from ndg.httpsclient.subj_alt_name import SubjectAltName
    
    
# Note that RFC6962 doesn't define a way to fetch public keys for logs
# per section 5.2, so keys should be fetched from http://www.certificate-transparency.org/known-logs
# Note that keys are stored in the log json file and that they should be decoded as PEM 
    
def main(args):
    if len(args) <= 1:
       print "Usage getentries.py startindex endindex"
       sys.exit(1)
    elif args[0].isdigit() == False or args[1].isdigit() == False:
       print "Usage getentries.py startindex endindex" 
       sys.exit(1)
    startindex = int(args[0])
    endindex = int(args[1])
    
    operation = 'ct/v1/get-entries'
    url = 'http://ct.googleapis.com/aviator/{}'.format(operation)
    
    
    params = urllib.urlencode({'start':startindex,'end':endindex - 1})
    
    s = Session()
    r = Request('GET',
    '{}?{}'.format(url,params),
    )
    
    prepped = r.prepare()
    r = s.send(prepped)
    if r.status_code == 200:
	entries = r.json()['entries']
	print entries
    else:
	print r.status_code
	print r.text

    
    
if __name__ == "__main__":
    main(sys.argv[1:])
