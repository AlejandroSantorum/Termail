################################################################################
#   Authors:                                                                   #
#       · Alejandro Santorum Varela - alejandro.santorum@estudiante.uam.es     #
#                                     alejandro.santorum@gmail.com             #
#   Date: Apr 14, 2019                                                         #
#   File: termail_client.py                                                    #
#   Project: Termail Messeger Service - project for Communication Networks II  #
#   Version: 1.1                                                               #
################################################################################
from termail_util import *
from crypto_util import *
import socket as skt
import os
import shutil
import getpass as gp
# Public and private keys for RSA algorithm
from Crypto.PublicKey import RSA

##############################################
### USEFUL FILES AND FOLDERS
RESOURCES_FOLDER = "clients_resources/"
RSA_KEYS_FOLDER = "clients_keys/"
SERVER_RSA_PUBL_KEY_FILE = "server_RSA_publ_key.pem"
PRIV_RSA_KEY_FILE = "priv_RSA_key.pem"
PUBL_RSA_KEY_FILE = "publ_RSA_key.pem"
##############################################
### USEFUL MACROS
ERROR = -1
SUCCESS = 0
REGISTER = 1
SIGN_IN = 2
EXIT = 3
USERNAME = 1
SUBJECT = 2
MSG = 3
MSG_ID = 1
NBITS = 64
##############################################

class TermailClient:
    '''
    TermailClient class
    Created the Termail Client to handle its functionality

    Attributes:
        server_ip : ip where the server is binded
        server_port : port where the server is binded
        verbose : whether to print progress messages to stdout.
        client_skt : server-client socket
        recv_size : maximum number of bytes that can be received in a single connection
        server_publ_key : server RSA public key
        server_publ_key_file : server RSA public key file
        priv_RSA_key : client's RSA private key
        publ_RSA_key : client's RSA public key
        priv_RSA_key_file : client's RSA private key file
        publ_RSA_key_file : client's RSA public key file
        p : prime for Diffie-Hellman's handshake
        g : generator for Diffie-Hellman's handshake
        a : user's number for Diffie-Hellman's handshake
        A : g^a (mop p)
        B : server's number for Diffie Hellman's handshake
        K : Diffie-Hellman's symmetric key
        strK : Dffie-Hellman's symm key converted to string

    Typical use:
        Shown at if __name__ == '__main__':
    '''

    def __init__(self, server_ip, server_port, verbose, recv_size=4096):
        self.server_ip = server_ip
        self.server_port = server_port
        self.verbose = verbose
        # Socket
        self.client_skt = -1
        # Maximum buffer size to get data from server
        self.recv_size = recv_size
        # RSA keys
        self.server_publ_key = None
        self.server_publ_key_file = None
        self.priv_RSA_key = None
        self.publ_RSA_key = None
        self.priv_RSA_key_file = None
        self.publ_RSA_key_file = None
        # Diffie-Hellman numbers
        self.p = None
        self.g = None
        self.a = None
        self.A = None
        self.B = None
        self.K = None
        self.strK = None
        # Opening socket and connecting Termail server
        self._open_socket()


    ################################################################
    # login
    # Input:
    #   - self: termail client instance
    # Output:
    #   - REGISTER, SIGN_IN or EXIT macros on success,
    #       raises ValueError otherwise
    # Description:
    #   It asks the user what he/she wants to do: register, sign in
    #   or exit the client, returning his/her choice
    ################################################################
    def login(self):
        while 1:
            try:
                print("Select one option:")
                print("["+str(REGISTER)+"] Register")
                print("["+str(SIGN_IN)+"] Sign in")
                print("["+str(EXIT)+"] Exit")
                mode = int(input())
                if mode > EXIT or mode < REGISTER:
                    print("Please, introduce a valid option")
                else:
                    return mode
            except ValueError:
                print("Please, introduce a valid option")


    ################################################################
    # _open_socket (private)
    # Input:
    #   - self: termail client instance
    # Output:
    #   - None
    # Description:
    #   It opens a TCP socket at the initialized server IP + port
    ################################################################
    def _open_socket(self):
        # Opening socket internet/TCP
        self.client_skt = skt.socket(skt.AF_INET, skt.SOCK_STREAM)
        # Establishing connection
        self.client_skt.connect((self.server_ip, self.server_port))


    ################################################################
    # _diffie_hellman_handshake (private)
    # Input:
    #   - self: termail client instance
    # Output:
    #   - None
    # Description:
    #   It generates all the diffie-hellman constants: p, g, a, A
    #   and sends to the server the needed information for the
    #   handshake, waiting for its answer
    ################################################################
    def _diffie_hellman_handshake(self):
        self.p = get_random_nbit_prime(NBITS)
        self.g = get_element_in_Zp(self.p)
        self.a = get_randint_range(1, self.p-1)
        self.A = pow(self.g, self.a, self.p)
        msg = "SETUP_DH "+str(self.p)+" "+str(self.g)+" "+str(self.A)
        # Sending command
        self.client_skt.send(msg.encode())
        # Receiving answer
        B = self.client_skt.recv(self.recv_size)
        self.B = int(B.decode())
        self.K = pow(self.B, self.a, self.p)
        # Verbosity
        if self.verbose:
            print(">>> Calculated prime (p): ", self.p)
            print(">>> Calculated generator (g): ", self.g)
            print(">>> Calculated a (random int between 1 and p-1): ", self.a)
            print(">>> Calculated A (g^a): ", self.A)
            print(">>> Received B (g^b): ", self.B)
            print(">>> K (shared key): ", self.K)
            print("")
        self.strK = str(self.K).encode()


    ################################################################
    # _get_server_public_key (private)
    # Input:
    #   - self: termail client instance
    # Output:
    #   - None
    # Description:
    #   It aks for the server's RSA public key with the command
    #   SERVER_PUBLIC_KEY. After recieving its answer, the RSA
    # public key is stored in a file
    ################################################################
    def _get_server_public_key(self):
        # Asking for server public key to send user data safely
        msg = "SERVER_PUBLIC_KEY"
        # Sending message to server
        self.client_skt.send(msg.encode())
        server_answer = self.client_skt.recv(self.recv_size)
        self.server_publ_key = server_answer.decode()
        self.server_publ_key_file = RESOURCES_FOLDER+SERVER_RSA_PUBL_KEY_FILE
        f = open(self.server_publ_key_file, "wb")
        f.write(server_answer)
        f.close()


    ################################################################
    # _recv_decrypt_verify (private)
    # Input:
    #   - self: termail client instance
    #   - caller_func: name of the function what called this one
    # Output:
    #   - decrypted command
    # Description:
    #   It receives a server answer, decrypts it, verifies its
    #   digital sign and returns the decrypted+verified answer
    #   on success. It raises and exception+ERROR on error case
    ################################################################
    def _recv_decrypt_verify(self, caller_func):
        # Waiting for response
        server_answer = self.client_skt.recv(self.recv_size)
        decrypted_answer, signature = decrypt_command(server_answer, self.strK, verbose=self.verbose)
        try:
            verify_digital_sign(decrypted_answer, signature, self.server_publ_key_file, verbose=self.verbose)
        except Exception as err:
            msg = "Invalid signature at "+caller_func+": "+str(err)
            print(msg)
            return ERROR
        return decrypted_answer.decode()


    ################################################################
    # register
    # Input:
    #   - self: termail client instance
    # Output:
    #   - SUCCESS if everything went ok, ERROR otherwise
    # Description:
    #   It asks the user for its nickname+password, generates his/her
    #   RSA keys, operates Diffie-Hellman handshake with the Termail
    #   server and signs up the user into the server
    ################################################################
    def register(self):
        name = input("Introduce nickname to be registered: ")
        while 1:
            password = gp.getpass("Introduce password: ")
            password2 = gp.getpass("Reintroduce password again: ")
            if password == password2:
                break
            print("Password does not match. Try again")

        # Getting server RSA public key to send data sefely
        self._get_server_public_key()

        # Generating user RSA keys
        try:
            temp = "_temp/"
            privKF_temp = RESOURCES_FOLDER+RSA_KEYS_FOLDER+name+temp+PRIV_RSA_KEY_FILE
            publKF_temp = RESOURCES_FOLDER+RSA_KEYS_FOLDER+name+temp+PUBL_RSA_KEY_FILE
            path_temp = RESOURCES_FOLDER+RSA_KEYS_FOLDER+name+temp
            try:
                os.mkdir(path_temp)
            except OSError as err:
                pass
            self.priv_RSA_key, self.publ_RSA_key = generate_RSA_keys(privKF_temp, publKF_temp)
            self.priv_RSA_key_file = privKF_temp
            self.publ_RSA_key_file = publKF_temp
        except ValueError as err:
            print("Unable to generate client RSA keys: "+str(err))
            return ERROR

        # Negotiating DH's session key with Termail server
        self._diffie_hellman_handshake()
        # Preparing command
        msg = "REGISTER "+name+" "+password+" "
        msg = msg.encode()
        msg += self.publ_RSA_key
        # Encrypting command (at registration signature wont be verified)
        cipher_msg = encrypt_command(msg, str(self.K).encode(), self.priv_RSA_key_file, verbose=self.verbose)
        # Sending message to server
        self.client_skt.send(cipher_msg)
        # Receiving encrypted data
        answer = self._recv_decrypt_verify("registration")
        # Removing temporary keys folder
        shutil.rmtree(path_temp, ignore_errors=True)
        # Checking server answer
        if answer == ERROR:
            return ERROR
        print(answer)
        answer_aux = answer.split()
        if answer_aux[0] == "Unable":
            return ERROR
        else:
            # Creating real keys folder and files
            privKF = RESOURCES_FOLDER+RSA_KEYS_FOLDER+name+"/"+PRIV_RSA_KEY_FILE
            publKF = RESOURCES_FOLDER+RSA_KEYS_FOLDER+name+"/"+PUBL_RSA_KEY_FILE
            path = RESOURCES_FOLDER+RSA_KEYS_FOLDER+name
            self.priv_RSA_key_file = privKF
            self.publ_RSA_key_file = publKF
            try:
                os.mkdir(path)
            except OSError as err:
                pass
            privKF_f = open(privKF, "wb")
            privKF_f.write(self.priv_RSA_key)
            privKF_f.close()
            publKF_f = open(publKF, "wb")
            publKF_f.write(self.publ_RSA_key)
            publKF_f.close()
            return SUCCESS


    ################################################################
    # sign_in
    # Input:
    #   - self: termail client instance
    # Output:
    #   - SUCCESS on success, ERROR otherwise
    # Description:
    #   It asks the user for its nickname+password, autheticating him/her
    #   in the Termail server
    ################################################################
    def sign_in(self):
        name = input("Introduce nickname: ")
        password = gp.getpass("Introduce password: ")

        # Negotiating DH's session key with Termail server
        self._diffie_hellman_handshake()
        # Getting server RSA public key to send data sefely
        self._get_server_public_key()

        # Storing RSA keys files
        privKF = RESOURCES_FOLDER+RSA_KEYS_FOLDER+name+"/"+PRIV_RSA_KEY_FILE
        publKF = RESOURCES_FOLDER+RSA_KEYS_FOLDER+name+"/"+PUBL_RSA_KEY_FILE
        self.priv_RSA_key_file = privKF
        self.publ_RSA_key_file = publKF

        # Preparing command
        msg = "SIGN_IN "+name+" "+password
        msg_bytes = msg.encode()
        try:
            cipher_msg = encrypt_command(msg_bytes, str(self.K).encode(), privKF, verbose=self.verbose)
        except Exception:
            print("There is not any user with nickname \'"+name+"\' in the database. Try it again")
            return ERROR
        # Sending message to server
        self.client_skt.send(cipher_msg)
        # Receiving encrypted data
        answer = self._recv_decrypt_verify("logging in")
        if answer == ERROR:
            return ERROR
        print(answer)
        answer_aux = answer.split()
        if answer_aux[0] == "Unable":
            return ERROR
        else:
            # Getting keys from the files where they're stored
            self.priv_RSA_key = RSA.import_key(open(privKF).read())
            self.publ_RSA_key = RSA.import_key(open(publKF).read())
            return SUCCESS


    ################################################################
    # print_help
    # Input:
    #   - self: termail client instance
    # Output:
    #   - None
    # Description:
    #   It prints on the terminal all the commands' inforamtion
    ################################################################
    def print_help(self):
        print("Available commands:")
        print("· HELP\n\t-> shows all commands")
        print("· SIGN_OUT\n\t-> closes the connection with the Termail server")
        print("· LIST_USERS\n\t-> sends to Termail server a request to get the users' list")
        print("· SEND_MSG <Username> <Subject> <Message>\n\t-> sends message to a given user")
        print("· LIST_MSGS\n\t-> lists all your received messages")
        print("· READ_MSG <Message ID>\n\t-> reads message with the given ID")


    ################################################################
    # sign_out
    # Input:
    #   - self: termail client instance
    # Output:
    #   - None
    # Description:
    #   It communicates Termail server we are closing the connection
    ################################################################
    def sign_out(self):
        # Preparing command
        msg = "SIGN_OUT"
        msg_bytes = msg.encode()
        cipher_msg = encrypt_command(msg_bytes, str(self.K).encode(), self.priv_RSA_key_file, verbose=self.verbose)

        # Sending message to server
        self.client_skt.send(cipher_msg)
        # Closing socket
        self.client_skt.close()


    ################################################################
    # list_users
    # Input:
    #   - self: termail client instance
    # Output:
    #   - None
    # Description:
    #   It requests the Termail server the list of registered users
    #   and prints it on the terminal
    ################################################################
    def list_users(self):
        # Preparing command
        msg = "LIST_USERS"
        msg_bytes = msg.encode()
        cipher_msg = encrypt_command(msg_bytes, str(self.K).encode(), self.priv_RSA_key_file, verbose=self.verbose)
        # Sending message to server
        self.client_skt.send(cipher_msg)
        # Receiving encrypted data
        answer = self._recv_decrypt_verify("listing users")
        print(answer)


    ################################################################
    # send_msg
    # Input:
    #   - self: termail client instance
    #   - to_name: string that represents an username
    #   - subject: string (with no blankspaces) that represents a message subject
    #   - msg: string that represents a message
    # Output:
    #   - None
    # Description:
    #   It sends a message to the user 'to_name', with the subject 'subject'
    ################################################################
    def send_msg(self, to_name, subject, msg):
        # Preparing command
        msg = "SEND_MSG "+to_name+" "+subject+" "+msg
        msg_bytes = msg.encode()
        cipher_msg = encrypt_command(msg_bytes, str(self.K).encode(), self.priv_RSA_key_file, verbose=self.verbose)
        # Sending message to server
        self.client_skt.send(cipher_msg)
        # Receiving encrypted data
        answer = self._recv_decrypt_verify("sending message")
        print(answer)


    ################################################################
    # list_messages
    # Input:
    #   - self: termail client instance
    # Output:
    #   - None
    # Description:
    #   It requests the Termail server the list of the message to
    #   the caller user, printing a brief summary of the terminal.
    #   Later, an user can read a single message using its ID
    ################################################################
    def list_messages(self):
        # Preparing command
        msg = "LIST_MSGS"
        msg_bytes = msg.encode()
        cipher_msg = encrypt_command(msg_bytes, str(self.K).encode(), self.priv_RSA_key_file, verbose=self.verbose)
        # Sending message to server
        self.client_skt.send(cipher_msg)
        # Receiving encrypted data
        answer = self._recv_decrypt_verify("listing messages")
        print(answer)


    ################################################################
    # read_msg
    # Input:
    #   - self: termail client instance
    #   - msg_id: integer that represents a message ID
    # Output:
    #   - None
    # Description:
    #   It requests the Termail server the information of the message
    #   with ID='msg_id' and prints it on the terminal
    ################################################################
    def read_msg(self, msg_id):
        # Preparing command
        msg = "READ_MSG "+msg_id
        msg_bytes = msg.encode()
        cipher_msg = encrypt_command(msg_bytes, str(self.K).encode(), self.priv_RSA_key_file, verbose=self.verbose)
        # Sending message to server
        self.client_skt.send(cipher_msg)
        # Receiving encrypted data
        answer = self._recv_decrypt_verify("reading message")
        print(answer)



if __name__ == "__main__":
    verbose = 0
    server_ip = '127.0.0.1'
    server_port = 5005

    if len(sys.argv) == 2 and sys.argv[1] == "-v":
        verbose = 1
    elif len(sys.argv) >= 3: #__name__ IP PORT
        server_ip = sys.argv[1]
        try:
            server_port = int(sys.argv[2])
        except ValueError:
            print("ERROR: Please, introduce a valid integer port between 5000 and 65535")
            exit()
        if len(sys.argv) == 4 and sys.argv[3] == "-v":
            verbose = 1

    # Creating TermailClient
    try:
        termail = TermailClient(server_ip, server_port, verbose)
    except Exception as err:
        print("Unable to initialize Termail Client: ", err)
        exit()

    # Start panel: register, sign in or exit
    while 1:
        mode = termail.login()
        try:
            if mode == REGISTER:
                if termail.register() == SUCCESS:
                    break # Registered successfully
            elif mode == SIGN_IN:
                if termail.sign_in() == SUCCESS:
                    break # Signed in successfully
            elif mode == EXIT:
                print("Exit successfully")
                exit()
            else:
                print("Error: Login mode failed")
        except skt.error as err:
            print("Socket error: "+str(err))
            exit()
        except OSError as err:
            print("OS Error: "+str(err))
            exit()
        except KeyboardInterrupt:
            print("Exiting Termail client")
            exit()

    # Once registered or signed in, you can send several commands
    while 1:
        try:
            command = input("Introduce command: ")
            cmd_items = command.split()
            if len(cmd_items) == 0:
                # User has introduced a blank command
                print("Do not introduce blank commands")
                continue
            elif cmd_items[0] == "HELP":
                termail.print_help()
            elif cmd_items[0] == "SIGN_OUT":
                termail.sign_out()
                print("Exiting Termail client")
                break
            elif cmd_items[0] == "LIST_USERS":
                termail.list_users()
            elif cmd_items[0] == "SEND_MSG":
                if len(cmd_items) < 4: # Error
                    print("Insufficient arguments for SEND_MSG command")
                    print("SEND_MSG <Username> <Subject> <Message>")
                    continue
                message = prepare_msg(cmd_items)
                termail.send_msg(cmd_items[USERNAME], cmd_items[SUBJECT], message)
            elif cmd_items[0] == "LIST_MSGS":
                termail.list_messages()
            elif cmd_items[0] == "READ_MSG":
                if len(cmd_items) < 2:
                    print("Insufficient arguments for READ_MSG command")
                    print("SEND_MSG <Message ID>")
                    continue
                termail.read_msg(cmd_items[MSG_ID])
            else:
                print("Invalid command. Use HELP command if needed")
        except skt.error as err:
            print("Socket error: "+str(err))
            termail.sign_out()
            break
        except KeyboardInterrupt:
            print("Exiting Termail client")
            termail.sign_out()
            break
