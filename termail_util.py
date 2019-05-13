################################################################################
#   Authors:                                                                   #
#       · Alejandro Santorum Varela - alejandro.santorum@estudiante.uam.es     #
#                                     alejandro.santorum@gmail.com             #
#   Date: Apr 14, 2019                                                         #
#   File: termail_util.py                                                      #
#   Project: Termail Messeger Service - project for Communication Networks II  #
#   Version: 1.1                                                               #
################################################################################

# Hash SHA256
from Crypto.Hash import SHA256
from crypto_util import *
# Public and private keys for RSA algorithm
from Crypto.PublicKey import RSA


################################################################
# prepare_msg
# Input:
#   - array_str: array of strings
# Output:
#   - a string that represents a message
# Description:
#   It joins a given array of strings into a unique string
################################################################
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


################################################################
# prepare_msg
# Input:
#   - args: array of strings containing a RSA key
#   - start_index: index where the RSA key begins
# Output:
#   - a string that represents a RSA key
# Description:
#   It joins the RSA key given the splitted command
################################################################
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


################################################################
# encrypt_command
# Input:
#   - command: string that represents a command
#   - K: Diffie-Hellman constant
#   - server_priv_RSA_key_file (optional): file of the sender RSA key
#   - verbose (optional): flag that indicates Whether to print
#       progress messages to stdout. Default 0 (deactivated).
# Output:
#   - init vector + ciphered command
# Description:
#   It encrypts a given command, signing it if a private RSA key file
#   is provided. It raises an Exception on error case
################################################################
def encrypt_command(command, K, sender_priv_RSA_key_file=None, verbose=0):
    try:
        if verbose:
            print(">>> Encrypting command: "+str(command)+"\n")
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


################################################################
# dencrypt_command
# Input:
#   - command: string that represents a encrypted command
#   - K: Diffie-Hellman constant
#   - sign_flag (optional): flag that indicates if the message
#       contains a digital sign concatenated on it
#   - verbose (optional): flag that indicates Whether to print
#       progress messages to stdout. Default 0 (deactivated).
# Output:
#   - decrypted command, signature if sign_flag = 1 or
#       just the decrypted command if sign_flag != 1
# Description:
#   It decrypts a given command. If sign_flag = 1, it also splits
#   the command in decrypted real command + signature
################################################################
def decrypt_command(command, K, sign_flag=1, verbose=0):
    try:
        if verbose:
            print(">>> Decrypting command\n")
        # Hashing the Diffie-Hellmans key to transform it into a 256b key
        symm_key_h = SHA256.new(K)
        symm_key = symm_key_h.digest()
        if sign_flag == 1:
            # Decrypting message using AES256
            real_command, signature = decrypt_AES256_CBC(command, symm_key, sign_flag=1)
            if verbose:
                print(">>> Decrypted command: "+str(real_command)+"\n")
            return real_command, signature
        else:
            real_command = decrypt_AES256_CBC(command, symm_key, sign_flag=0)
            if verbose:
                print(">>> Decrypted command: "+str(real_command)+"\n")
            return real_command
    except Exception as err:
        raise Exception("Decrypting ERROR: " + str(err))


################################################################
# verify_digital_sign
# Input:
#   - message: signed message
#   - signature: sign of the provided message
#   - sender_publ_RSA_key_file: RSA public key file of the message's sender
#   - verbose (optional): flag that indicates Whether to print
#       progress messages to stdout. Default 0 (deactivated).
# Output:
#   - Just raises an Exception if the digital sign does not match
# Description:
#   It verifies if a digital sign of a message is truly correct,
#   providing sender's RSA public key.
################################################################
def verify_digital_sign(message, signature, sender_publ_RSA_key_file, verbose=0):
    if verbose:
        print(">>> Verifying message digital sign\n")
    sender_publ_RSA_key = RSA.import_key(open(sender_publ_RSA_key_file).read())
    # Verifying signature
    if verify_signature(message, signature, sender_publ_RSA_key) != True:
        raise Exception("Decrypting ERROR: Signature does not match")
