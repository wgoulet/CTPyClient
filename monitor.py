import os
import base64
import json
import urllib
from requests import Session, Request
from OpenSSL import crypto



operation = 'ct/v1/get-sth'
url = 'http://ct.googleapis.com/aviator/{}'.format(operation)
ofile = './ofile.out'


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
f = open(ofile,'w')

if r.status_code == 200:
    entries = r.json()['entries']
    for i in entries:
        f.write('Leaf:\n')
        f.write(i['leaf_input'])
        f.write('Extra Data:\n')
        f.write(i['extra_data'])
        f.write('\n')

    f.close()

else:
    print r.status_code
    print r.text
