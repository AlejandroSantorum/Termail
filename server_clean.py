################################################################################
#   Authors:                                                                   #
#       · Alejandro Santorum Varela - alejandro.santorum@estudiante.uam.es     #
#                                     alejandro.santorum@gmail.com             #
#   Date: Apr 14, 2019                                                         #
#   File: server_clean.py                                                      #
#   Project: Termail Messeger Service - project for Communication Networks II  #
#   Version: 1.0                                                               #
################################################################################
import os
import shutil

######################################################
# Folders to clean
RESOURCES_FOLDER = "server_resources/"
SERVER_KEYS_FOLDER = "server_RSA_keys/"
SERVER_CLIENTS_KEYS_FOLDER = "server_clients_keys/"
######################################################

def clean_clients_keys():
    client_key_folder = RESOURCES_FOLDER+SERVER_CLIENTS_KEYS_FOLDER
    for file in os.listdir(client_key_folder):
        file_path = os.path.join(client_key_folder, file)
        try:
            if os.path.isfile(file_path):
                # Deleting all files in the given folder
                os.unlink(file_path)
        except Exception as exc:
            print("Unable to clean server clients keys: ", exc)
    return


def clean_RSA_keys():
    RSA_key_folder = RESOURCES_FOLDER+SERVER_KEYS_FOLDER
    for file in os.listdir(RSA_key_folder):
        file_path = os.path.join(RSA_key_folder, file)
        try:
            if os.path.isfile(file_path):
                # Deleting all files in the given folder
                os.unlink(file_path)
        except Exception as exc:
            print("Unable to clean server RSA keys: ", exc)
    return


if __name__ == "__main__":
    # Deleting clients keys
    clean_clients_keys()
    # Deleting server RSA keys
    clean_RSA_keys()
