import os
import base64
from requests import Session, Request
from OpenSSL import crypto
from pyasn1.codec.der.decoder import decode
from pyasn1_modules import rfc2459



url = 'http://ct.googleapis.com/aviator/ct/v1/get-roots'


s = Session()
r = Request('GET',
             url)

prepped = r.prepare()

r = s.send(prepped)

if r.status_code == 200:
   roots = r.json()

# RFC 6962 defines the certificate objects as base64 encoded certs.
# Importantly, these are not PEM formatted certs but base64 encoded
# ASN.1 (DER) encoded

for i in roots:
   certs = roots[i]
   for k in certs:
       try:
           certobj = crypto.load_certificate(crypto.FILETYPE_ASN1,base64.b64decode(k))
           subject = certobj.get_subject()
           cert,rest = decode(base64.b64decode(k),asn1Spec=rfc2459.Certificate())
           cert = cert['tbsCertificate']
           subj = cert['subject']
           rdnseq = subj[0]
           subjstr = ''
           for r in rdnseq:
               oid,value = r[0]
               subjstr = subjstr + ':' + str(value)
           print subjstr
          
           #print 'CN={},OU={},O={},L={},S={},C={}'.format(subject.commonName,
           #                                           subject.organizationalUnitName,
           #                                           subject.organizationName,
           #                                           subject.localityName,
           #                                           subject.stateOrProvinceName,
           #                                           subject.countryName)
       except Exception as e:
           print e 
           #print subject.get_components()
