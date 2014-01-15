import os
import base64
import json
import urllib
import io
import struct
from requests import Session, Request
from OpenSSL import crypto
    
    
    
def main():
    operation = 'ct/v1/get-sth'
    url = 'http://ct.googleapis.com/aviator/{}'.format(operation)
    
    s = Session()
    r = Request('GET', url)
    
    prepped = r.prepare()
    
    r = s.send(prepped)
    
    numcerts = 0
    
    if r.status_code == 200:
        sth = r.json()
        numcerts = sth['tree_size']
    
    operation = 'ct/v1/get-entries'
    url = 'http://ct.googleapis.com/aviator/{}'.format(operation)
    
    endindex = numcerts - 1
    startindex = numcerts - 10
    
    params = urllib.urlencode({'start':startindex,'end':endindex})
    
    
    s = Session()
    
    r = Request('GET',
                 '{}?{}'.format(url,params),
                 )
    
    prepped = r.prepare()
    
    r = s.send(prepped)
    
    if r.status_code == 200:
        entries = r.json()['entries']
        for i in entries:
            print "End entity cert"
            parse_leafinput(base64.b64decode(i['leaf_input']))
            print "Signing cert chain"
            parse_asn1certs(base64.b64decode(i['extra_data']))
    else:
        print r.status_code
        print r.text
    
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
        print_cert(cert)
        bcount += certlen
        
def print_cert(cert):
    try:
        certobj = crypto.load_certificate(crypto.FILETYPE_ASN1,cert)
        subject = certobj.get_subject()
        print 'CN={},OU={},O={},L={},S={},C={}'.format(subject.commonName,
                                                       subject.organizationalUnitName,
                                                       subject.organizationName,
                                                       subject.localityName,
                                                       subject.stateOrProvinceName,
                                                       subject.countryName)
    except:
        print subject.get_components()
    
             
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
    
    print_cert(cert)
    
main()
