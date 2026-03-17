from anytree import NodeMixin, RenderTree,PostOrderIter,PreOrderIter,LevelOrderGroupIter
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import hashlib
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import datetime
import random
import os
import string
import socket
import binascii
import struct
import time


############CHANGE ME##########
certificatepath="certificate.pem"
privitekeypath="private.key"
outputname="blah.der"

##These should get added to a list
boolean=b"\x01"
stringtype=b"\x10"
integer=b"\x02"
sequence=b"\x30"
set1=b"\x31"
bitstring=b"\x03"
##Can shorten this later
choice0=b"\xa0"
choice1=b"\xa1"
choice2=b"\xa2"
choice3=b"\xa3"
choice4=b"\xa4"
choice5=b"\xa5"
choice6=b"\xa6"
choice7=b"\xa7"
choice8=b"\xa8"
choice9=b"\xa9"
choice10=b"\xaa"
nulltype=b"\x05"
octet=b"\x04"
str1_name=b"\x1b"
ia5=b"\x16"
utf8=b"\x0c"
dirstr=b"\x13"
GeneralizedTime=b"\x18"
utctime=b"\x17"
und1=b"\x80"
und6=b"\x86"
oid=b"\x06"
raw=0#b"\xff"


def encode_der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    elif length < 0x10000:
        return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
    else:
        raise ValueError(f"Length {length} too large for this encoder")


def der_sequence(*items: bytes) -> bytes:
    body = b"".join(items)
    return bytes([0x30]) + encode_der_length(len(body)) + body


def der_bitstring(data: bytes) -> bytes:
    payload = bytes([0x00]) + data
    return bytes([0x03]) + encode_der_length(len(payload)) + payload


def sha256_with_rsa_algorithm_identifier() -> bytes:
    oid = bytes([
        0x06, 0x09,                          # OID tag + length
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, # 1.2.840.113549
        0x01, 0x01, 0x0B                     # .1.11
    ])
    null = bytes([0x05, 0x00])               # NULL
    return der_sequence(oid, null)


def sign_tbs_certificate(
    tbs_certificate: bytes,
    private_key: RSAPrivateKey,
) -> bytes:
    if not isinstance(private_key, RSAPrivateKey):
        raise TypeError("private_key must be an RSAPrivateKey instance")
    if not tbs_certificate:
        raise ValueError("tbs_certificate must not be empty")

    signature: bytes = private_key.sign(
        tbs_certificate,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )

    algorithm_identifier = sha256_with_rsa_algorithm_identifier()
    signature_bit_string  = der_bitstring(signature)

    certificate = der_sequence(
        tbs_certificate,
        algorithm_identifier,
        signature_bit_string,
    )

    return certificate

def calculatelength(parent):
    for node in PostOrderIter(parent):
        for children in LevelOrderGroupIter(node,maxlevel=2):
            for node2 in children:
                if node.name != node2.name:
                   #print("parent: "+str(node.name)+" child: "+str(node2.name)+" child length: "+str(node2.length)+ " child lsize: "+str(node2.lsize)+" parent size: "+str(node.length))
                    ##Note: probably a shorter way to code this.. but we arn't writing prod code, so whatever
                    if node2.length < 0x100:
                        node2.lsize=2
                    elif node2.length < 0x1000:
                        node2.lsize=3
                    elif node2.length < 0x10000:
                        node2.lsize=4
                    elif node2.length < 0x100000:
                        node2.lsize=5
                    elif node2.length < 0x1000000:
                        node2.lsize=6
                    elif node2.length < 0x10000000:
                        node2.lsize=7
                    if node2.tag==0:
                        node2.lsize=0    
                      
                    node.length += (node2.length  + node2.lsize)
                    
                    if node2.tag != 0:
                        node.length += node2.tsize
                  #  print("parent size: "+str(node.length)+" lsize: "+str(node2.lsize))    

    return 0

def build(parent):
    rawdata=b""
    if parent.tag !=0:
        rawdata+=parent.tag   
    if parent.length < 0x100:
        rawdata+=b"\x81"+(parent.length).to_bytes(1,'big')
    elif parent.length < 0x1000:
        rawdata+=b"\x82"+(parent.length).to_bytes(2,'big')
    elif parent.length < 0x10000:  
        rawdata+=b"\x83"+(parent.length).to_bytes(3,'big')
    elif parent.length < 0x100000:      
        rawdata+=b"\x84"+(parent.length).to_bytes(4,'big')
    elif parent.length < 0x1000000:      
        rawdata+=b"\x85"+(parent.length).to_bytes(5,'big')
    elif parent.length < 0x10000000:      
        rawdata+=b"\x86"+(parent.length).to_bytes(6,'big')    
    if parent.data !=0:
        rawdata+=parent.data# +rawdata[0::]  
    for node in PreOrderIter(parent):
                if node.name != parent.name:
                    if node.tag !=0:   
                        rawdata+=node.tag
                    #to do: if bigger then 1 byte, make it bigger and keep track so we can bubble it upwards
                        if node.length < 0x100:
                            rawdata+=b"\x81"+(node.length).to_bytes(1,'big')
                        elif node.length < 0x1000:
                            rawdata+=b"\x82"+(node.length).to_bytes(2,'big')
                        elif node.length < 0x10000:  
                            rawdata+=b"\x83"+(node.length).to_bytes(3,'big')
                        elif node.length < 0x100000:      
                            rawdata+=b"\x84"+(node.length).to_bytes(4,'big')
                        elif node.length < 0x1000000:      
                            rawdata+=b"\x85"+(node.length).to_bytes(5,'big')
                        elif node.length < 0x10000000:      
                            rawdata+=b"\x86"+(node.length).to_bytes(6,'big')        
                    if node.data !=0:
                        rawdata+=node.data 
    return rawdata 

def random_char(y):
    return ''.join(random.choice(string.ascii_letters) for x in range(y))


def set_data(node,data,tag):
    if data:
        node.data=data
        node.length=len(data)
    if tag:
        node.tag = tag
        node.tsize = len(tag)

class AsnC(NodeMixin):
    def __init__(self,name="Empty",tag=0,length=0,lsize=1,tsize=0,data=0,parent=None,children=None):
        super(AsnC, self).__init__()
        self.name = name
        self.lsize=lsize
        self.tag = tag
        if self.tag !=0:
            self.tsize=len(tag)#tsize
        else: 
            self.tsize=0
        self.data = data
        if data != 0:  
            self.length = len(data)
        else:     
            self.length=0
        self.parent = parent
        if children:
            self.children = children       



def buildcert():

    sgnd_cert=AsnC("sgnd_cert")
    
    cert_version=AsnC("cert_version",parent=sgnd_cert)
    cert_version_int=AsnC("cert_version_int",parent=cert_version)
    cert_serialnumber=AsnC("cert_serialnumber",parent=sgnd_cert)
    cert_signature=AsnC("cert_signature",parent=sgnd_cert)
    cert_signature_oid=AsnC("cert_signature_oid",parent=cert_signature)
    cert_signature_hash=AsnC("cert_signature_hash",parent=cert_signature)

    cert_issuer=AsnC("cert_issuer",parent=sgnd_cert)
    cert_issuer_set_item1=AsnC("cert_issuer_set_item1",parent=cert_issuer)
    cert_issuer_item1=AsnC("cert_issuer_item1",parent=cert_issuer_set_item1)
    cert_issuer_item1_oid=AsnC("cert_issuer_item1_oid",parent=cert_issuer_item1)
    cert_issuer_item1_IA5=AsnC("cert_issuer_item1_IA5",parent=cert_issuer_item1)
    cert_issuer_set_item2=AsnC("cert_issuer_set_item2",parent=cert_issuer)
    cert_issuer_item2=AsnC("cert_issuer_item2",parent=cert_issuer_set_item2)
    cert_issuer_item2_oid=AsnC("cert_issuer_item2_oid",parent=cert_issuer_item2)
    cert_issuer_item2_IA5=AsnC("cert_issuer_item2_IA5",parent=cert_issuer_item2)
    cert_issuer_set_item3=AsnC("cert_issuer_set_item3",parent=cert_issuer)
    cert_issuer_item3=AsnC("cert_issuer_item3",parent=cert_issuer_set_item3)
    cert_issuer_item3_oid=AsnC("cert_issuer_item3_oid",parent=cert_issuer_item3)
    cert_issuer_item3_dirstr=AsnC("cert_issuer_item3_dirstr",parent=cert_issuer_item3)


    cert_validity=AsnC("cert_validity",parent=sgnd_cert)
    cert_validity_notbefore=AsnC("cert_validity_notbefore",parent=cert_validity)
    cert_validity_notafter=AsnC("cert_validity_notafter",parent=cert_validity)
    
    cert_subject=AsnC("cert_subject",parent=sgnd_cert)
    cert_subject_set_item1=AsnC("cert_subject_set_item1",parent=cert_subject)
    cert_subject_item1=AsnC("cert_subject_item1",parent=cert_subject_set_item1)
    cert_subject_item1_oid=AsnC("cert_subject_item1_oid",parent=cert_subject_item1)
    cert_subject_item1_IA5=AsnC("cert_subject_item1_IA5",parent=cert_subject_item1)
    cert_subject_set_item2=AsnC("cert_subject_set_item2",parent=cert_subject)
    cert_subject_item2=AsnC("cert_subject_item2",parent=cert_subject_set_item2)
    cert_subject_item2_oid=AsnC("cert_subject_item2_oid",parent=cert_subject_item2)
    cert_subject_item2_IA5=AsnC("cert_subject_item2_IA5",parent=cert_subject_item2)
    cert_subject_set_item3=AsnC("cert_subject_set_item3",parent=cert_subject)
    cert_subject_item3=AsnC("cert_subject_item3",parent=cert_subject_set_item3)
    cert_subject_item3_oid=AsnC("cert_subject_item3_oid",parent=cert_subject_item3)
    cert_subject_item3_dirstr=AsnC("cert_subject_item3_dirstr",parent=cert_subject_item3)
    cert_subject_set_item4=AsnC("cert_subject_set_item4",parent=cert_subject)
    cert_subject_item4=AsnC("cert_subject_item4",parent=cert_subject_set_item4)
    cert_subject_item4_oid=AsnC("cert_subject_item4_oid",parent=cert_subject_item4)
    cert_subject_item4_dirstr=AsnC("cert_subject_item4_dirstr",parent=cert_subject_item4)

    cert_subpubkeyinfo=AsnC("cert_subpubkeyinfo",parent=sgnd_cert)
    cert_extensions=AsnC("cert_extensions",parent=sgnd_cert)
    cert_extensions_seq=AsnC("cert_extensions_seq",parent=cert_extensions)
    cert_extension1=AsnC("cert_extension1",parent=cert_extensions_seq)
    cert_extension1_oid=AsnC("cert_extension1_oid",parent=cert_extension1)
    cert_extensions1_octet1=AsnC("cert_extensions1_octet1",parent=cert_extension1)
    cert_extensions1_octet2=AsnC("cert_extensions1_octet2",parent=cert_extensions1_octet1)

    cert_extension2=AsnC("cert_extension2",parent=cert_extensions_seq)
    cert_extension2_oid=AsnC("cert_extension2_oid",parent=cert_extension2)
    cert_extensions2_octet1=AsnC("cert_extensions2_octet1",parent=cert_extension2)
    cert_extensions2_seq=AsnC("cert_extensions2_seq",parent=cert_extensions2_octet1)
    cert_extensions2_und=AsnC("cert_extensions2_und",parent=cert_extensions2_seq)


    cert_extension5=AsnC("cert_extension5",parent=cert_extensions_seq)
    cert_extension5_oid=AsnC("cert_extension5_oid",parent=cert_extension5)
    cert_extensions5_octet1=AsnC("cert_extensions5_octet1",parent=cert_extension5)

    cert_extension6=AsnC("cert_extension6",parent=cert_extensions_seq)
    cert_extension6_oid=AsnC("cert_extension6_oid",parent=cert_extension6)
    cert_extensions6_bool=AsnC("cert_extensions6_bool",parent=cert_extension6)
    cert_extensions6_octet1=AsnC("cert_extensions6_octet1",parent=cert_extension6)
    cert_extensions6_bitstring=AsnC("cert_extensions6_bitstring",parent=cert_extensions6_octet1)

    cert_extension7=AsnC("cert_extension7",parent=cert_extensions_seq)
    cert_extension7_oid=AsnC("cert_extension7_oid",parent=cert_extension7)
    cert_extensions7_octet1=AsnC("cert_extensions7_octet1",parent=cert_extension7)
    cert_extensions7_seq=AsnC("cert_extensions7_seq",parent=cert_extensions7_octet1)
    cert_extensions7_oid1=AsnC("cert_extensions7_oid1",parent=cert_extensions7_seq)
    cert_extensions7_oid2=AsnC("cert_extensions7_oid2",parent=cert_extensions7_seq)
    cert_extensions7_oid3=AsnC("cert_extensions7_oid3",parent=cert_extensions7_seq)

    cert_extension8=AsnC("cert_extension8",parent=cert_extensions_seq)
    cert_extension8_oid=AsnC("cert_extension8_oid",parent=cert_extension8)
    cert_extensions8_octet1=AsnC("cert_extensions8_octet1",parent=cert_extension8)
    cert_extensions8_seq=AsnC("cert_extensions8_seq",parent=cert_extensions8_octet1)
    cert_extensions8_choice=AsnC("cert_extensions8_choice",parent=cert_extensions8_seq)
    cert_extensions8_oid2=AsnC("cert_extensions8_oid2",parent=cert_extensions8_choice)
    cert_extensions8_choice2=AsnC("cert_extensions8_choice2",parent=cert_extensions8_choice)
    cert_extensions8_utf8=AsnC("cert_extensions8_utf8",parent=cert_extensions8_choice2)

    cert_extension9=AsnC("cert_extension9",parent=cert_extensions_seq)
    cert_extension9_oid=AsnC("cert_extension9_oid",parent=cert_extension9)
    cert_extensions9_octet1=AsnC("cert_extensions9_octet1",parent=cert_extension9)
    cert_extensions9_seq=AsnC("cert_extensions9_seq",parent=cert_extensions9_octet1)
    cert_extensions9_choice=AsnC("cert_extensions9_choice",parent=cert_extensions9_seq)
    cert_extensions9_oid2=AsnC("cert_extensions9_oid2",parent=cert_extensions9_choice)
    cert_extensions9_choice2=AsnC("cert_extensions9_choice2",parent=cert_extensions9_choice)
    cert_extensions9_octet=AsnC("cert_extensions9_octet",parent=cert_extensions9_choice2)

    cert_extension10=AsnC("cert_extension10",parent=cert_extensions_seq)
    cert_extension10_oid=AsnC("cert_extension10_oid",parent=cert_extension10)
    cert_extensions10_octet1=AsnC("cert_extensions10_octet1",parent=cert_extension10)
    cert_extensions10_seq=AsnC("cert_extensions10_seq",parent=cert_extensions10_octet1)
    cert_extensions10_item1_seq=AsnC("cert_extensions10_item1_seq",parent=cert_extensions10_seq)
    cert_extensions10_item1_oid=AsnC("cert_extensions10_item1_oid",parent=cert_extensions10_item1_seq)
    cert_extensions10_item1_int=AsnC("cert_extensions10_item1_int",parent=cert_extensions10_item1_seq)
    cert_extensions10_item2_seq=AsnC("cert_extensions10_item2_seq",parent=cert_extensions10_seq)
    cert_extensions10_item2_oid=AsnC("cert_extensions10_item2_oid",parent=cert_extensions10_item2_seq)
    cert_extensions10_item2_int=AsnC("cert_extensions10_item2_int",parent=cert_extensions10_item2_seq)
    cert_extensions10_item3_seq=AsnC("cert_extensions10_item3_seq",parent=cert_extensions10_seq)
    cert_extensions10_item3_oid=AsnC("cert_extensions10_item3_oid",parent=cert_extensions10_item3_seq)
    cert_extensions10_item4_seq=AsnC("cert_extensions10_item4_seq",parent=cert_extensions10_seq)
    cert_extensions10_item4_oid=AsnC("cert_extensions10_item4_oid",parent=cert_extensions10_item4_seq)

    serialN=b"\x3b\x00\x00\x00\x03\xe6\x49\x0d\xf8\xc7\xa4\x27\x9e\x00\x00\x00\x00\x00\x03"

    #set_data(certs_seq,None,sequence)
    set_data(sgnd_cert,None,sequence)
    set_data(cert_version,None,choice0)
    set_data(cert_version_int,b"\x02",integer)
    set_data(cert_serialnumber,serialN,integer)#\x00\x00\x00\x16
    set_data(cert_signature,None,sequence)
    set_data(cert_signature_oid,b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b",oid)
    set_data(cert_signature_hash,None,nulltype)
    issuerfield1=b"com123S"
    issuerfield2=b"bear123"
    issuerfield3=b"bear123"
    set_data(cert_issuer,None,sequence)
    set_data(cert_issuer_set_item1,None,set1)    
    set_data(cert_issuer_item1,None,sequence)
    set_data(cert_issuer_item1_oid,b"\x09\x92\x26\x89\x93\xf2\x2c\x64\x01\x19",oid)
    set_data(cert_issuer_item1_IA5,issuerfield1,ia5)
    set_data(cert_issuer_set_item2,None,set1) 
    set_data(cert_issuer_item2,None,sequence)
    set_data(cert_issuer_item2_oid,b"\x09\x92\x26\x89\x93\xf2\x2c\x64\x01\x19",oid)
    set_data(cert_issuer_item2_IA5,issuerfield2,ia5)
    set_data(cert_issuer_set_item3,None,set1)     
    set_data(cert_issuer_item3,None,sequence)
    set_data(cert_issuer_item3_oid,b"\x55\x04\x03",oid)
    set_data(cert_issuer_item3_dirstr,issuerfield3,dirstr)

    set_data(cert_validity,None,sequence)
    set_data(cert_validity_notbefore,b"\x32\x34\x30\x31\x30\x35\x30\x33\x35\x38\x34\x32\x5a",utctime)
    set_data(cert_validity_notafter,b"\x32\x35\x30\x31\x30\x34\x30\x33\x35\x38\x34\x32\x5a",utctime)
    subjectfield1=b"com123"
    subjectfield2=b"bear123"
    subjectfield3=b"Users123"

    set_data(cert_subject,None,sequence)
    set_data(cert_subject_set_item1,None,set1)    
    set_data(cert_subject_item1,None,sequence)
    set_data(cert_subject_item1_oid,b"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x01",oid)
    set_data(cert_subject_item1_IA5,subjectfield1,ia5)
    set_data(cert_subject_set_item2,None,set1) 
    set_data(cert_subject_item2,None,sequence)
    set_data(cert_subject_item2_oid,b"\x09\x92\x26\x89\x93\xf2\x2c\x64\x01\x19",oid)
    set_data(cert_subject_item2_IA5,subjectfield2,ia5)
    set_data(cert_subject_set_item3,None,set1)     
    set_data(cert_subject_item3,None,sequence)
    set_data(cert_subject_item3_oid,b"\x55\x04\x03",oid)
    set_data(cert_subject_item3_dirstr,subjectfield3,dirstr)
    set_data(cert_subject_set_item4,None,set1)     
    set_data(cert_subject_item4,None,sequence)
    set_data(cert_subject_item4_oid,b"\x55\x04\x03",oid)
    set_data(cert_subject_item4_dirstr,b"\x74\x65\x73\x74",dirstr)

    with open(certificatepath, "rb") as cert_file:
        cert = x509.load_pem_x509_certificate(cert_file.read())

    public_key_bytes = cert.public_key().public_bytes(encoding=Encoding.DER,format=PublicFormat.SubjectPublicKeyInfo)

    set_data(cert_subpubkeyinfo,public_key_bytes[4:],sequence)   
    set_data(cert_extensions,None,choice3)
    set_data(cert_extensions_seq,None,sequence)
    set_data(cert_extension1,None,sequence)
    set_data(cert_extension1_oid,b"\x55\x1d\x0e",oid)
    set_data(cert_extensions1_octet1,None,octet)
    set_data(cert_extensions1_octet2,b"\x43\x2e\xc5\xa2\x4a\x90\xa3\x1c\x8b\x2c\x6a\xc7\x0d\x80\xf8\x07\x8b\x4a\x7e\xe6",octet)
    ##Authkey
    set_data(cert_extension2,None,sequence)
    set_data(cert_extension2_oid,b"\x55\x1d\x23",oid)
    set_data(cert_extensions2_octet1,None,octet)
    set_data(cert_extensions2_seq,None,sequence)
    set_data(cert_extensions2_und,b"\x26\xce\x5a\x40\x51\x62\xfd\x52\xd9\x0a\x88\xbd\xda\xd3\x1e\xa4\xb1\x4a\x44\xe4",und1)



    #id-ms-certificate-template-name
    set_data(cert_extension5,None,sequence)
    set_data(cert_extension5_oid,b"\x2b\x06\x01\x04\x01\x82\x37\x14\x02",oid)
    set_data(cert_extensions5_octet1,b"\x1e\x08\x00\x55\x00\x73\x00\x65\x00\x72",octet)
    ##id-ce-keyUsage
    set_data(cert_extension6,None,sequence)
    set_data(cert_extension6_oid,b"\x55\x1d\x0f",oid)
    set_data(cert_extensions6_bool,b"\xff",boolean) 
    set_data(cert_extensions6_octet1,None,octet)
    set_data(cert_extensions6_bitstring,b"\x05\xa0",bitstring)
    #id-ce-extkeyusage
    set_data(cert_extension7,None,sequence)
    set_data(cert_extension7_oid,b"\x55\x1d\x25",oid)
    set_data(cert_extensions7_octet1,None,octet)
    set_data(cert_extensions7_seq,None,sequence)
    set_data(cert_extensions7_oid1,b"\x2b\x06\x01\x04\x01\x82\x37\x0a\x03\x04",oid)
    set_data(cert_extensions7_oid2,b"\x2b\x06\x01\x05\x05\x07\x03\x04",oid)
    set_data(cert_extensions7_oid3,b"\x2b\x06\x01\x05\x05\x07\x03\x02",oid)
    ##id-ce-subjectaltname
    set_data(cert_extension8,None,sequence)
    set_data(cert_extension8_oid,b"\x55\x1d\x11",oid)
    set_data(cert_extensions8_octet1,None,octet)
    set_data(cert_extensions8_seq,None,sequence)
    set_data(cert_extensions8_choice,None,choice0)
    set_data(cert_extensions8_oid2,b"\x01",oid)
    set_data(cert_extensions8_choice2,None,choice0)
    set_data(cert_extensions8_utf8,b"\x62\x6c\x61\x68\x40\x62\x6c\x61\x68\x2e\x63\x6f\x6d",utf8)
    ##iso.3.6.1.4.1.311.25.2
    set_data(cert_extension9,None,sequence)
    set_data(cert_extension9_oid,b"\x2b\x06\x01\x04\x01\x82\x37\x19\x02",oid)
    set_data(cert_extensions9_octet1,None,octet)
    set_data(cert_extensions9_seq,None,sequence)
    set_data(cert_extensions9_choice,None,choice0)
    set_data(cert_extensions9_oid2,b"\x2b\x06\x01\x04\x01\x82\x37\x19\x02\x01",oid)
    set_data(cert_extensions9_choice2,None,choice0)
    set_data(cert_extensions9_octet,b"\x53\x2d\x31\x2d\x35\x2d\x32\x31\x2d\x31\x35\x37\x35\x39\x31\x34\x36\x35\x39\x2d\x33\x38\x38\x30\x31\x38\x30\x2d\x31\x35\x34\x39\x37\x31\x32\x38\x38\x38\x2d\x31\x31\x31\x30",octet)
    ##id-smime-capabilities
    set_data(cert_extension10,None,sequence)
    set_data(cert_extension10_oid,b"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x0f",oid)
    set_data(cert_extensions10_octet1,None,octet)
    set_data(cert_extensions10_seq,None,sequence)
    set_data(cert_extensions10_item1_seq,None,sequence)
    set_data(cert_extensions10_item1_oid,b"\x2a\x86\x48\x86\xf7\x0d\x03\x02",oid)
    set_data(cert_extensions10_item1_int,b"\x00\x80",integer)
    set_data(cert_extensions10_item2_seq,None,sequence)
    set_data(cert_extensions10_item2_oid,b"\x2a\x86\x48\x86\xf7\x0d\x03\x04",oid)
    set_data(cert_extensions10_item2_int,b"\x00\x80",integer)
    set_data(cert_extensions10_item3_seq,None,sequence)
    set_data(cert_extensions10_item3_oid,b"\x2b\x0e\x03\x02\x07",oid)
    set_data(cert_extensions10_item4_seq,None,sequence)
    set_data(cert_extensions10_item4_oid,b"\x2a\x86\x48\x86\xf7\x0d\x03\x07",oid)


    calculatelength(sgnd_cert)

    data=build(sgnd_cert)
    return data 

data = buildcert()
with open(privitekeypath, "rb") as key_file:
    private_key = load_pem_private_key(
        key_file.read(),
        password=None  
    )

data = sign_tbs_certificate(data, private_key)

with open(outputname,"wb") as f:
    f.write(data)




