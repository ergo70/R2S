# -*- coding: utf-8 -*-
"""
Created on Sun May  6 22:33:19 2018

@author: Ernst-Georg Schmid
"""

#from os import stat
#from sys import exit
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.x509.oid import NameOID
from io import BytesIO
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.exceptions import InvalidSignature
from uuid import uuid4
import datetime
import time
import json

NUM_BLOCKS = 10

POOL_TARGET = int('0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 16)

DIFFICULTY = 10 # Set to positive integer for self-signing certificate mode

KEYSIZE = 4096

KEYPASS = b'anTigone180'

MAX_YEAR = 3000

NODE_NAME = 'sn-{}'.format(str(uuid4()))

base_block = {'payload': 'Genesis block'}

#if oct(stat('keys/sign_key.pem').st_mode & 0o777) != '0o600':
#    exit("File permissions on keys/sign_key.pem must be 0600!")

print(NODE_NAME)

certificates_seen = {}


def selfsigning(difficulty):
    return difficulty > 0


def calculate_difficulty_threshold(difficulty):
    """
    Summary line.

    Extended description of function.

    Parameters
    ----------
    difficulty : int
        Description of arg1l

    Returns
    -------
    int
        Description of return value

    """
    try:
        return POOL_TARGET / difficulty
    except ZeroDivisionError:
        return 0


def mkcert():
    """
    Make a self-signed X.509 certificate.

    Make a self-signed X.509 certificate for signing new blocks.

    Returns
    -------
    cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey
        The private key of the certificate

    cryptography.x509.Certificate
        The X.509 certificate

    string
        Fingerprint of the certificate in hex

    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size = KEYSIZE,backend = default_backend())
    public_key = private_key.public_key()
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, NODE_NAME),]))
    builder = builder.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, NODE_NAME),]))
    builder = builder.not_valid_before(datetime.datetime.today())
    builder = builder.not_valid_after(datetime.datetime(MAX_YEAR, 1, 1))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(public_key)
    builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(NODE_NAME)]), critical = False)
    builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical = True)
    builder = builder.add_extension(x509.KeyUsage(digital_signature=True, content_commitment=True, key_encipherment = False, data_encipherment = False, key_agreement = False, key_cert_sign = False, crl_sign = False, encipher_only=False, decipher_only = False), critical = True)
    certificate = builder.sign(private_key = private_key, algorithm = hashes.SHA256(), backend = default_backend())

    return private_key, certificate, certificate.fingerprint(hashes.SHA256()).hex()


def rts(difficulty):
    if selfsigning(difficulty):
        i=1

        while True:
            pk, cert, cert_fp = mkcert()
            if int(cert_fp, 16) <= calculate_difficulty_threshold(difficulty):
                break
            i+=1

        print("Iterations: " + str(i))
    else:
        with open("keys/sign_key.pem", "rb") as key_file:
            pk = serialization.load_pem_private_key(key_file.read(),password=KEYPASS,backend=default_backend())
        cert = x509.load_pem_x509_certificate(open('keys/sign_cert.pem', 'rb').read(), default_backend())
        cert_fp = cert.fingerprint(hashes.SHA256()).hex()

    return pk, cert, cert_fp


def encode_cert(certificate):
    pem = BytesIO()
    pem.write(certificate.public_bytes(serialization.Encoding.PEM))

    encoded = urlsafe_b64encode(pem.getvalue()).decode('ascii', 'strict')

    pem.close()

    return encoded


def decode_cert(certificate):
    pem = urlsafe_b64decode(certificate)

    return x509.load_pem_x509_certificate(pem, default_backend())


def block_certificate(block):
    return decode_cert(block['certificate'])


def block_hash(block):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(str(block['number']).encode('ascii', 'strict'))
    digest.update(str(block['difficulty']).encode('ascii', 'strict'))
    digest.update(block['fingerprint'].encode('ascii', 'strict'))
    digest.update(block['certificate'].encode('ascii', 'strict'))
    digest.update(block['payload'].encode('ascii', 'strict'))
    digest.update(block['prev_blockhash'].encode('ascii', 'strict'))

    return digest.finalize()


def verify_block(prev_block, block):
    if prev_block and block_hash(prev_block).hex() != block['prev_blockhash']:
        return False

    certificate = decode_cert(block['certificate'])
    signature = bytes.fromhex(block['signature'])

    blockhash = block_hash(block)

    public_key = certificate.public_key()

    try:
        public_key.verify(signature, blockhash,
                          padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                          utils.Prehashed(hashes.SHA256()))
    except InvalidSignature:
        return False

    return True


def iscertunique(certs_seen, block):
    if block['fingerprint'] in certs_seen:
        print('Duplicate certificate found.')
        return False

    certs_seen[block['fingerprint']] = True

    print('Certificate unique.')

    return True


def make_block(block, prev_block, difficulty):
    global at
    start = time.monotonic()
    block['number'] = next_block_number()
    block['difficulty'] = difficulty

    pk, cert, cert_fp = rts(difficulty)

    block['fingerprint'] = cert_fp

    block['certificate'] = encode_cert(cert)

    if prev_block:
        block['prev_blockhash'] = block_hash(prev_block).hex()
        #print(block['prev_blockhash'])
    else:
        block['prev_blockhash'] = '0'

    blockhash = block_hash(block)

    signature = pk.sign(blockhash,padding.PSS(mgf = padding.MGF1(hashes.SHA256()),salt_length = padding.PSS.MAX_LENGTH),utils.Prehashed(hashes.SHA256()))

    block['signature'] = signature.hex()

    end = time.monotonic()

    print (end - start)

    return block


def next_block_number():
    return time.monotonic()


def test_chain(num_blocks):
    blockchain = []

    for i in range(0, num_blocks):
        prev_block = None

        if i > 0:
            prev_block = json.loads(blockchain[-1])
            base_block['payload'] = str(i)

        next_block = make_block(base_block,prev_block,DIFFICULTY)

        if selfsigning(DIFFICULTY):
            if iscertunique(certificates_seen, next_block):
                blockchain.append(json.dumps(next_block))
            else:
                print('Block rejected')
        else:
            blockchain.append(json.dumps(next_block))

    prev_block = None

    for entry in blockchain:
        block = json.loads(entry)

        print(verify_block(prev_block, block))
        print(block)

        prev_block = block


test_chain(NUM_BLOCKS)