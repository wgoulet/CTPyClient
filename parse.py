import io
import struct
import sys
import base64
from OpenSSL import crypto

infile = open(sys.argv[1],'rb')


# MerkleTreeLeaf -> Version, MerkleLeafType, TimestampedEntry

rawbytes = base64.b64decode(infile.read())

leaf = io.BytesIO(rawbytes)

version = leaf.read(1)

ver = struct.unpack(">B",version)

print ver[0]

ltype = leaf.read(1)

lt = struct.unpack(">B",ltype)

print lt[0]

timestamp = leaf.read(8)

ts = struct.unpack(">Q",timestamp)

print ts[0]

entrytype = leaf.read(2)

etype = struct.unpack(">H",entrytype)

print etype[0]

certlength = leaf.read(3)

clen = struct.unpack(">I",'\x00' + certlength)

print clen[0]

cert = leaf.read(clen[0])

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



#print rawbytes
print len(rawbytes)

infile.close()
