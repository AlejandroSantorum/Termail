################################################################################
#   Authors:                                                                   #
#       · Alejandro Santorum Varela - alejandro.santorum@estudiante.uam.es     #
#   Date: April 15, 2019                                                       #
#   File: crypto_util.py                                                       #
#   Project: Termail                                                           #
#   Version: 1.5                                                               #
################################################################################

# Pseudo-random byte generator
from Crypto.Random import get_random_bytes
# Pseudo-random intenger generator
from Crypto.Random.random import randint
# Pseudo-random prime generator
from Crypto.Util.number import getPrime
# Symmetric cipher (AES) and asymmetric cipher (RSA)
from Crypto.Cipher import AES, PKCS1_OAEP
# Padding to cipher using AES in mode CBC
from Crypto.Util.Padding import pad, unpad
# Digital sign
from Crypto.Signature import pkcs1_15
# Public and private keys for RSA algorithm
from Crypto.PublicKey import RSA
# Hash SHA256
from Crypto.Hash import SHA256
# Other
from math import gcd
import sys


################################################################
# generate_RSA_keys
# Input:
#   - priv_key_file: file where private key is going to be stored
#   - publ_key_file: file where public key is going to be stored
# Output:
#   - private key & public key generated
# Description:
#   It generates a RSA public key and private key couple
#   Raises ValueError in error case
################################################################
def generate_RSA_keys(priv_key_file, publ_key_file):
    try:
        # Initializing RSA
        key = RSA.generate(2048)
        # Getting private key and saving it into a file
        private_key = key.exportKey()
        file_out = open(priv_key_file, "wb")
        file_out.write(private_key)
        file_out.close()
        # Getting public key and saving it into a file
        public_key = key.publickey().exportKey()
        file_out = open(publ_key_file, "wb")
        file_out.write(public_key)
        file_out.close()
        # Returning both keys successfully
        return private_key, public_key
    except:
        raise ValueError("ERROR: Unable to generate RSA keys")


################################################################
# digital_sign
# Input:
#   - message: plaint text to be signed
#   - sender_priv_key_file: file where sender private key is stored
# Output:
#   - signature (signed message)
# Description:
#   It signes message's hash (hashed using SHA256)
#   Raises ValueError in error case
################################################################
def digital_sign(message, sender_priv_key_file):
    try:
        # Getting key from the file where it's stored
        key = RSA.import_key(open(sender_priv_key_file).read())
        # Hashing the data with SHA256
        h = SHA256.new(message)
        # Signature
        signature = pkcs1_15.new(key).sign(h)
        return signature
    except:
        raise ValueError("ERROR: Unable to sign the message")


################################################################
# encrypt_AES256_CBC
# Input:
#   - message: message to encrypt
#   - digital_sign (optional): signature to be added at the beginning
#       of the message
# Output:
#   - ciphered text (containing signature+message)
#   - iv
#   - symmetric key
# Description:
#   It puts together the signature with the message, and then encrypts
#   the text using AES 256 bits with IV of 16 bytes in CBC mode
#   Raises ValueError in error case
################################################################
SESSION_KEY_BYTES = 32
BLOCK_SIZE = 16
def encrypt_AES256_CBC(message, digital_sign=None):
    try:
        # Concatenating signature+plain text if signature is provided
        if digital_sign != None:
            text = digital_sign+message
        else:
            text = message
        # Padding text, so its length is multiple of block size (16)
        text_pad = pad(text, BLOCK_SIZE)
        # Getting session key (symmetric key) of 32 bytes
        session_key = get_random_bytes(SESSION_KEY_BYTES)
        # Initialization vector of legth as the block size (16)
        iv = get_random_bytes(BLOCK_SIZE)
        # Symmetric AES256 Cipher
        cipher = AES.new(session_key, AES.MODE_CBC, iv=iv)
        ciphertext = cipher.encrypt(text_pad)
        # Returning ciphered text + symmetric key (session_key + iv)
        return ciphertext, iv, session_key
    except:
        raise ValueError("ERROR: Unable to cipher message using AES256 CBC mode")


################################################################
# encrypt_RSA2048
# Input:
#   - symm_key: symmetric key to be encrypted
#   - receiver_publ_key: RSA public key of the receiver of the message
# Output:
#   - ciphered symmetric key
# Description:
#   It cipheres a symmetric key using RSA 2048 bits to be deciphered
#   by a certain user
#   Raises ValueError in error case
################################################################
def encrypt_RSA2048(symm_key, receiver_publ_key):
    try:
        # Getting RSA cipher
        cipher_rsa = PKCS1_OAEP.new(receiver_publ_key)
        # Ciphering symmetric key
        cipherkey = cipher_rsa.encrypt(symm_key)
        return cipherkey
    except:
        raise ValueError("ERROR: Unable to cipher symmetric key using RSA2048")


################################################################
# decrypt_RSA2048
# Input:
#   - digital_envelope: text where a symmetric key is suppossed
#       to be encrypted
#   - priv_key_file: file where private key is stored
# Output:
#   - decrypted symmetric key
# Description:
#   It deciphers a symmetric key that has been ciphered using RSA2048
#   Raises ValueError in error case
################################################################
def decrypt_RSA2048(digital_envelope, priv_key_file):
    try:
        # Getting private key of the receiver of the ciphered message
        priv_key = RSA.import_key(open(priv_key_file).read())
        # Getting RSA decrypter
        cipher_rsa = PKCS1_OAEP.new(priv_key)
        # Deciphering symmetric key
        symm_key = cipher_rsa.decrypt(digital_envelope)
        return symm_key
    except:
        raise ValueError("ERROR: Unable to decipher symmetric key using RSA2048")


################################################################
# decrypt_AES256_CBC
# Input:
#   - cipher_msg: message to be deciphered
#   - symm_key: symmetryc key used to cipher the message
#   - sign_flag (optional): flag that indicates the message contains
#       a signature, so the method separates the message and the sign
# Output:
#   - deciphered text if sign_flag=0, or deciphered text + digital_sign
#       if sign_flag=1
# Description:
#   It decipheres a ciphered message using AES 256 bits with IV of
#   16 bytes in CBC mode with the provided symmetric key
#   Raises ValueError in error case
################################################################
SIGN_SIZE = 256
def decrypt_AES256_CBC(cipher_msg, symm_key, sign_flag=0):
    try:
        # Getting Session key and Initialization vector
        session_key = symm_key
        iv = cipher_msg[:BLOCK_SIZE]
        cipher_msg = cipher_msg[BLOCK_SIZE:]
        # Getting AES256 decrypter
        cipher = AES.new(session_key, AES.MODE_CBC, iv=iv)
        # Getting plain text after deciphering
        text_pad = cipher.decrypt(cipher_msg)
        # Unpadding
        text = unpad(text_pad, BLOCK_SIZE)
        # Separating digital sign from message if sign_flag is ON (1)
        if sign_flag:
            digital_sign = text[:SIGN_SIZE]
            message = text[SIGN_SIZE:]
            return message, digital_sign
        else:
            return text
    except:
        raise ValueError("ERROR: Unable to decipher message using AES256 CBC mode")


def verify_signature(message, digital_sign, sender_publ_key):
    try:
        # Hash message
        h = SHA256.new(message)
        # Checking if hash of the ciphered message is equal to the digital sign
        pkcs1_15.new(sender_publ_key).verify(h, digital_sign)
        return True
    except:
        return False


def _check_coprime(n,m):
    return gcd(n,m)==1

def get_element_in_Zp(prime):
    while 1:
        aux = randint(2,prime)
        if _check_coprime(aux,prime):
            return aux
    return -1


def get_random_nbit_prime(n):
    return getPrime(n)

def get_randint_range(a,b):
    return randint(a,b)

# Testing module
if __name__ == "__main__":
    print("Test not implemented here")
