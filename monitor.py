import os
import base64
import json
import urllib
import io
import sys
import struct
import hashlib
import re
import time
import math
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
    autofetch = True
    first = 0
    second = 0

    if len(args) < 1:
       print "Usage monitor.py \"path to log public key\" [sth treesize 1] [sth treesize 2]"
       sys.exit(1)
    elif len(args) > 1:
	autofetch = False
	first = args[1]
	second = args[2]

    logkeypath = args[0]

    if autofetch == True:
        operation = 'ct/v1/get-sth'
	url = 'http://ct.googleapis.com/aviator/{}'.format(operation)
    
	s = Session()
	r = Request('GET', url)
	prepped = r.prepare()
	proxies = {
		#"http": "http://127.0.0.1:8080",
	}
	r = s.send(prepped,proxies=proxies)
    
	numcerts = 0
    
	if r.status_code == 200:
	    sth = r.json()
	    numcerts = sth['tree_size']

	logkey = open(logkeypath,'r').read()
	if verify_sth(sth,logkey) == False:
	    print 'Invalid log; signed tree head failed validation'
	    return 1
	else:
	    sth1 = sth

	# Get another STH, keep asking until we get another one different
	cacheval = re.search('\d+',r.headers['cache-control']).group(0)
	fetchct = 1
	delayval = 1

	while True:
	    time.sleep(int(cacheval))
	    print "STH fetch # {0}".format(fetchct)
	    fetchct += 1
	    r = s.send(prepped,proxies=proxies)
	    if r.status_code == 200:
		sth = r.json()
		if verify_sth(sth,logkey) == False:
		    print 'Invalid log; signed tree head failed validation'
		    return 1
		else:
		    sth2 = sth
		    delayval = int(math.log(fetchct))
		if sth1['timestamp'] != sth2['timestamp']:
		    break
	first = sth1['treesize']
	second = sth1['treesize']

    # Verify STHs by fetching consistency proof

    operation = 'ct/v1/get-sth-consistency'
    url = 'http://ct.googleapis.com/aviator/{}'.format(operation)
    s = Session()
    params = urllib.urlencode({'first':first,'second':second})
    r = Request('GET', '{}?{}'.format(url,params))
    prepped = r.prepare()
   
    r = s.send(prepped)
    if r.status_code == 200:
	print r.text


#    verify_entries(sth,leaves)
    
def parse_asn1certs(inder):
    #Certlist is variable size list of ASN.1Cert objects
    #so we have to get size of list, then we have to parse
    #the data in the list as individual ASN.1Cert objects
    inbytes = io.BytesIO(inder)
    maxlen = len(inder)
    #Per RFC5246, cert_list and ASN.1Cert are variable
    #length byte lists with max size of 2^24-1 bytes.
    #First 'n' bytes of the data specify the size,
    #where 'n' is the number of bytes to required to
    #store max of the list. Max val of 2^24-1 requires
    #3 bytes to store, so read first 3 bytes of cert_list
    #and ASN.1Cert to get actual size of the list
    certlistlen = inbytes.read(3)
    listlen, = struct.unpack(">I",'\x00' + certlistlen)
    certlist = inbytes.read(listlen)
    bcount = 0
    #After we read in whole list, need to advance IO
    #read pointer to skip over the length bytes for the
    # whole list
    inbytes.seek(3)
    while bcount < listlen:
        #Read in length bytes
        inlen = inbytes.read(3)
        bcount += 3
        certlen, = struct.unpack(">I",'\x00' + inlen)
        cert = inbytes.read(certlen)
        print_cert(cert,printraw=False)
        bcount += certlen
        
def print_cert(cert,printraw=False):
    #Certain there are better toolsets for this, but parse cert
    #subject and break it into the DN components that are important
    #if this fails, just dump the raw subject data as returned by 
    #openssl
    try:
        certobj = crypto.load_certificate(crypto.FILETYPE_ASN1,cert)
        if printraw:
            print crypto.dump_certificate(crypto.FILETYPE_PEM,certobj)
        
        subject = certobj.get_subject()
        print 'CN={},OU={},O={},L={},S={},C={}'.format(subject.commonName,
                                                       subject.organizationalUnitName,
                                                       subject.organizationName,
                                                       subject.localityName,
                                                       subject.stateOrProvinceName,
                                                       subject.countryName)
        #Get contents of subjectAltName extension 
        extct = certobj.get_extension_count()
        # Code copied blatently from https://gist.github.com/cato-/6551668/raw/9d0c4d5e1ba16b92c4f4a18e74e460c097676785/verify_cert.py
        # and ndg.httpsclient.ssl_peer_verification.ServerSSLCertVerification
        general_names = SubjectAltName()
        for i in range(extct):
            ext = certobj.get_extension(i)
            if ext.get_short_name() == 'subjectAltName':
                data = der_decoder.decode(ext.get_data(),asn1Spec=general_names)
                for names in data:
                    for entry in range(len(names)):
                        component = names.getComponentByPosition(entry)
                        print str(component.getComponent())
                bstr = io.BytesIO(ext.get_data())
                blen = len(bstr.read())
                bstr.seek(0)
                val = ''
	print subject.get_components()
    except:
	print "Unable to parse certificate subject"
    
             
def parse_leafinput(inder):
    
    # Skip ahead to location in the data where the x509_entry or
    # precert_entry are defined
    # MerkleTreeLeaf -> Version, MerkleLeafType, TimestampedEntry
    # TimestampedEntry -> timestamp,entry_type,x509_entry||precert_entry
    
    rawbytes = inder
    leaf = io.BytesIO(rawbytes)
    version = leaf.read(1)
    #MerkleLeafType
    ltype = leaf.read(1)
    #TimeStampedEntry 
    timestamp = leaf.read(8)
    entrytype = leaf.read(2)
    certlength = leaf.read(3)
    clen = struct.unpack(">I",'\x00' + certlength)
    cert = leaf.read(clen[0])
    if entrytype != 1:
	print_cert(cert)
    else:
	print "Pre-cert entry"

def verify_sth(sth_json,sigkey):
    # Signature is calculated over this structure
    # digitally-signed struct {
    #       Version version;
    #       SignatureType signature_type = tree_hash;
    #       uint64 timestamp;
    #       uint64 tree_size;
    #       opaque sha256_root_hash[32];
    #   } TreeHeadSignature;
    treehash = struct.pack(">B",1)
    version = struct.pack(">B",0)
    # put the decimal encoded values into byte buffers
    tstampbuf = struct.pack(">Q",sth_json["timestamp"])
    tsizebuf = struct.pack(">Q",sth_json["tree_size"])
    # convert base64 root hash to binary
    srhbuf = base64.b64decode(sth_json["sha256_root_hash"])
    buf = version + treehash + tstampbuf + tsizebuf + srhbuf

    # Per RFC 6962, either support RSA or ECDSA with NIST256p curves
    # determine this by deserializing TLS signature structure

    print base64.b64encode(buf)
    # Get SHA256 digest of buffer
    m = SHA256.new(buf)
    # convert base64 signature in message to binary
    sigbuf = base64.b64decode(sth_json["tree_head_signature"])
    b = io.BytesIO(sigbuf)
    hashalgo ,= struct.unpack(">b",b.read(1))
    sigalgo ,= struct.unpack(">b",b.read(1))
    # Signature is opaque data structure per RFC 5246. Length of the signature
    # is stored in first n bytes where n is number of bytes sufficient to hold max size
    # of signature
    # Defined as 
    # struct {
    #     SignatureAndHashAlgorithm algorithm;
    #     opaque signature<0..2^16-1>;
    #  } DigitallySigned;
    # 2 bytes needed to specify 2^16 - 1

    siglen ,= struct.unpack(">h",b.read(2))
    buf2 = b.read()
    if siglen != len(buf2):
	print 'Signature invalid; signature wrong length'
	return False


    # Verify the signature
    print sigkey
    # From RFC 5246 section 7.4.1.4.1 
    # enum {
    #      none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5),
    #      sha512(6), (255)
    #  } HashAlgorithm;

    #  enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), (255) }
    #    SignatureAlgorithm;

    if hashalgo == 4 and sigalgo == 3:
	vk = VerifyingKey.from_pem(sigkey)
	try:
	    vk.verify(buf2,buf,hashfunc=hashlib.sha256,
	    sigdecode=ecdsa.util.sigdecode_der)
	    print "The signature is authentic."
	except BadSignatureError:
		print "The signature is not authentic."
		return False
    else:
	print "Unsupported signature/hash algorithm"
	return False

    return True

def verify_entries(sth,entries):
    # Calculate hash of passed in entries
    print len(entries)
    calchash = get_hash(entries,algo='SHA256')
    print base64.b64encode(calchash)

def get_hash(entries,algo):
    n = len(entries)
    if n == 0:
	return 0
    if algo != 'SHA256':
	return 0
    if n == 1:
	buf = '0x00' + entries[0]
	return SHA256.new(buf).digest()
    else:
	k = n
	while True:
	    k -= 1
	    if is_power2(k):
		break
	return SHA256.new('0x01' + get_hash(entries[0:k],'SHA256') + get_hash(entries[k:n],'SHA256')).digest()

# From activestate recipies
# Author: A.Polino

def is_power2(num):
    'states if a number is a power of two'
    return num != 0 and ((num & (num - 1)) == 0)
    
if __name__ == "__main__":
    main(sys.argv[1:])
