################################################################################
#   Authors:                                                                   #
#       · Alejandro Santorum Varela - alejandro.santorum@estudiante.uam.es     #
#                                     alejandro.santorum@gmail.com             #
#   Date: Apr 14, 2019                                                         #
#   File: client_clean.py                                                      #
#   Project: Termail Messeger Service - project for Communication Networks II  #
#   Version: 1.0                                                               #
################################################################################
import os
import shutil

######################################################
# Folders to clean
RESOURCES_FOLDER = "clients_resources/"
RSA_KEYS_FOLDER = "clients_keys/"
######################################################

def clean_server_RSA_keys():
    RSA_key_folder = RESOURCES_FOLDER
    for file in os.listdir(RSA_key_folder):
        file_path = os.path.join(RSA_key_folder, file)
        try:
            if os.path.isfile(file_path):
                os.unlink(file_path)
        except Exception as exc:
            print("Unable to clean server RSA keys: ", exc)
    return


if __name__ == "__main__":
    clean_server_RSA_keys()
