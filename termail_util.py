# Hash SHA256
from Crypto.Hash import SHA256
from crypto_util import *
# Public and private keys for RSA algorithm
from Crypto.PublicKey import RSA

# Auxiliary function to allow users send messages with spaces through terminal input
def prepare_msg(array_str):
    msg = ""
    i = 3
    length = len(array_str)
    while i<length:
        msg += array_str[i]
        if i != length:
            msg += " "
        i += 1
    return msg


def parse_RSA_key(args, start_index):
    aux = ""
    i = start_index
    length = len(args)
    space_counter = 0
    linebreak = 0
    while i < length:
        aux += args[i]
        if space_counter<2 and linebreak<8:
            aux += " "
            space_counter += 1
        elif linebreak<8:
            aux += "\n"
            linebreak += 1
        else:
            aux += " "
        i += 1
    return aux


def encrypt_command(command, K, sender_priv_RSA_key_file=None):
    try:
        # Hashing the Diffie-Hellmans key to transform it into a 256b key
        symm_key_h = SHA256.new(K)
        symm_key = symm_key_h.digest()
        # Checking if the user wants to sign the command
        if sender_priv_RSA_key_file != None:
            # Digital sign of the command
            signature = digital_sign(command, sender_priv_RSA_key_file)
            # Ciphering message with AES256
            ciphertext, iv, aes_key = encrypt_AES256_CBC(command, digital_sign=signature, symm_key=symm_key)
        else:
            ciphertext, iv, aes_key = encrypt_AES256_CBC(command, symm_key=symm_key)
        # OBS: aes_key = symm_key in the case symm_key is provided to the encrypt_aes function
        return iv+ciphertext
    except Exception as err:
        raise Exception("Encrypting ERROR: " + str(err))


def decrypt_command(command, K, sign_flag=1):
    try:
        # Hashing the Diffie-Hellmans key to transform it into a 256b key
        symm_key_h = SHA256.new(K)
        symm_key = symm_key_h.digest()
        if sign_flag == 1:
            # Decrypting message using AES256
            real_command, signature = decrypt_AES256_CBC(command, symm_key, sign_flag=1)
            return real_command, signature
        else:
            real_command = decrypt_AES256_CBC(command, symm_key, sign_flag=0)
            return real_command
    except Exception as err:
        raise Exception("Decrypting ERROR: " + str(err))


def verify_digital_sign(message, signature, sender_publ_RSA_key_file):
    sender_publ_RSA_key = RSA.import_key(open(sender_publ_RSA_key_file).read())
    # Verifying signature
    if verify_signature(message, signature, sender_publ_RSA_key) != True:
        raise Exception("Decrypting ERROR: Signature does not match")
