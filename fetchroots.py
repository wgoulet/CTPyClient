import os
import base64
from requests import Session, Request
from OpenSSL import crypto



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
           print 'CN={},OU={},O={},L={},S={},C={}'.format(subject.commonName,
                                                      subject.organizationalUnitName,
                                                      subject.organizationName,
                                                      subject.localityName,
                                                      subject.stateOrProvinceName,
                                                      subject.countryName)
       except:
           print subject.get_components()
