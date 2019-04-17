from termail_util import *
from crypto_util import *
# Public and private keys for RSA algorithm
from Crypto.PublicKey import RSA
import socket as skt
import os

##############################################
RESOURCES_FOLDER = "clients_resources/"
RSA_KEYS_FOLDER = "clients_keys/"
PRIV_RSA_KEY_FILE = "priv_RSA_key.pem"
PUBL_RSA_KEY_FILE = "publ_RSA_key.pem"
##############################################
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

    def __init__(self, server_ip, server_port, recv_size=4096):
        self.server_ip = server_ip
        self.server_port = server_port
        # Socket
        self.client_skt = -1
        # Maximum buffer size to get data from server
        self.recv_size = recv_size
        # RSA keys
        self.server_publ_key = None
        self.priv_RSA_key = None
        self.publ_RSA_key = None
        # Diffie-Hellman numbers
        self.p = None
        self.g = None
        self.a = None
        self.A = None
        self.B = None


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


    def _open_socket(self):
        # Opening socket internet/TCP
        self.client_skt = skt.socket(skt.AF_INET, skt.SOCK_STREAM)
        # Establishing connection
        self.client_skt.connect((self.server_ip, self.server_port))


    def _diffie_hellman_handshake(self):
        self.p = get_random_nbit_prime(NBITS)
        self.g = get_element_in_Zp(self.p)
        self.a = get_randint_range(1, self.p-1)
        self.A = pow(self.g, self.a, self.p)
        msg = "SETUP_DH "+str(self.p)+" "+str(self.g)+" "+str(self.A)
        self.client_skt.send(msg.encode())
        B = self.client_skt.recv(self.recv_size)
        self.B = B.decode()


    def register(self):
        name = input("Introduce nickname to be registered: ")
        while 1:
            password = input("Introduce password: ")
            password2 = input("Reintroduce password again: ")
            if password == password2:
                break
            print("Password does not match. Try again")

        # Opening socket and connecting Termail server
        self._open_socket()

        # Asking for server public key to send user data safely
        msg = "SERVER_PUBLIC_KEY"
        # Sending message to server
        self.client_skt.send(msg.encode())
        server_answer = self.client_skt.recv(self.recv_size)
        self.server_publ_key = server_answer.decode()

        # Generating user RSA keys
        try:
            privKF = RESOURCES_FOLDER+RSA_KEYS_FOLDER+name+"/"+PRIV_RSA_KEY_FILE
            publKF = RESOURCES_FOLDER+RSA_KEYS_FOLDER+name+"/"+PUBL_RSA_KEY_FILE
            path = RESOURCES_FOLDER+RSA_KEYS_FOLDER+name
            try:
                os.mkdir(path)
            except OSError as err:
                pass
            self.priv_RSA_key, self.publ_RSA_key = generate_RSA_keys(privKF, publKF)
        except ValueError as err:
            print("Unable to generate client RSA keys: "+str(err))
            return ERROR

        # Negotiating DH's session key with Termail server
        self._diffie_hellman_handshake()
        # Preparing command
        msg = "REGISTER "+name+" "+password+" "
        msg = msg.encode()
        msg +=self.publ_RSA_key
        # Sending message to server
        self.client_skt.send(msg)
        # Waiting for response
        server_answer = self.client_skt.recv(self.recv_size)
        answer = server_answer.decode()
        print(answer)
        answer_aux = answer.split()
        if answer_aux[0] == "Unable":
            return ERROR
        else:
            return SUCCESS


    def sign_in(self):
        name = input("Introduce nickname: ")
        password = input("Introduce password: ")
        # Opening socket and connecting Termail server
        self._open_socket()

        # Negotiating DH's session key with Termail server
        self._diffie_hellman_handshake()

        # Preparing command
        msg = "SIGN_IN "+name+" "+password
        # Sending message to server
        self.client_skt.send(msg.encode())
        # Waiting for response
        server_answer = self.client_skt.recv(self.recv_size)
        answer = server_answer.decode()
        print(answer)
        answer_aux = answer.split()
        if answer_aux[0] == "Unable":
            return ERROR
        else:
            privKF = RESOURCES_FOLDER+RSA_KEYS_FOLDER+name+"/"+PRIV_RSA_KEY_FILE
            publKF = RESOURCES_FOLDER+RSA_KEYS_FOLDER+name+"/"+PUBL_RSA_KEY_FILE
            # Getting keys from the files where they're stored
            self.priv_RSA_key = RSA.import_key(open(privKF).read())
            self.publ_RSA_key = RSA.import_key(open(publKF).read())
            return SUCCESS


    def print_help(self):
        print("Available commands:")
        print("· HELP\n\t-> shows all commands")
        print("· SIGN_OUT\n\t-> closes the connection with the Termail server")
        print("· LIST_USERS\n\t-> sends to Termail server a request to get the users' list")
        print("· SEND_MSG <Username> <Subject> <Message>\n\t-> sends message to a given user")
        print("· LIST_MSGS\n\t-> lists all your received messages")
        print("· READ_MSG <Message ID>\n\t-> reads message with the given ID")


    def sign_out(self):
        # Preparing command
        msg = "SIGN_OUT"
        # Sending message to server
        self.client_skt.send(msg.encode())
        # Closing socket
        self.client_skt.close()


    def list_users(self):
        # Preparing command
        msg = "LIST_USERS"
        # Sending message to server
        self.client_skt.send(msg.encode())
        # Waiting for response
        server_answer = self.client_skt.recv(self.recv_size)
        print(server_answer.decode())

    def send_msg(self, to_name, subject, msg):
        # Preparing command
        msg = "SEND_MSG "+to_name+" "+subject+" "+msg
        # Sending message to server
        self.client_skt.send(msg.encode())
        # Waiting for response
        server_answer = self.client_skt.recv(self.recv_size)
        print(server_answer.decode())

    def list_messages(self):
        # Preparing command
        msg = "LIST_MSGS"
        # Sending message to server
        self.client_skt.send(msg.encode())
        # Waiting for response
        server_answer = self.client_skt.recv(self.recv_size)
        print(server_answer.decode())

    def read_msg(self, msg_id):
        # Preparing command
        msg = "READ_MSG "+msg_id
        # Sending message to server
        self.client_skt.send(msg.encode())
        # Waiting for response
        server_answer = self.client_skt.recv(self.recv_size)
        print(server_answer.decode())



if __name__ == "__main__":
    server_ip = '127.0.0.1'
    server_port = 5005

    termail = TermailClient(server_ip, server_port)
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
        #except Exception as err:
        #    print("An exception occurred: "+str(err))

    # Once registered or signed in, you can send several commands
    while 1:
        try:
            command = input("Introduce command: ")
            cmd_items = command.split()
            if len(cmd_items) == 0:
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
