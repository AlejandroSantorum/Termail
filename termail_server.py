################################################################################
#   Authors:                                                                   #
#       · Alejandro Santorum Varela - alejandro.santorum@estudiante.uam.es     #
#                                     alejandro.santorum@gmail.com             #
#   Date: Apr 14, 2019                                                         #
#   File: termail_server.py                                                    #
#   Project: Termail Messeger Service - project for Communication Networks II  #
#   Version: 1.1                                                               #
################################################################################
from termail_util import *
from crypto_util import *
import socket as skt
import threading as thr
import time

##############################################
RESOURCES_FOLDER = "server_resources/"
SERVER_KEYS_FOLDER = "server_RSA_keys/"
SERVER_CLIENTS_KEYS_FOLDER = "server_clients_keys/"
PRIV_KEY_FILE = "priv_RSA_key.pem"
PUBL_KEY_FILE = "publ_RSA_key.pem"
##############################################
ERROR = -1
SUCCESS = 0
CMD = 0
USERNAME = 1
PASSW = 2
PK = 3
SUBJECT = 2
MSG = 3
MSG_ID = 1
MODULO = 1
GENERATOR = 2
A_IND = 3
##############################################
USR_NOT_FOUND_DB_MSG = "User not found in the database"

total_msgs = 0
class Message:
    '''
    Message class
    It mission is to store a message in a proper way

    Attributes:
        __from : username of sender
        __to : username of receiver
        __subject : subject of the message (just one word)
        __msg : message sent
        __id : id of the message. Each message has an unique id

    Typical use:
        msg = Message("Jack", "Peter", "Confirmation_of_Entry", "You have been awarded...")
    '''

    def __init__(self, from_name, to_name, subject, msg):
        self.__from = from_name
        self.__to = to_name
        self.__subject = subject
        self.__msg = msg
        global total_msgs
        self.__id = total_msgs
        total_msgs += 1

    def get_from(self):
        return self.__from

    def get_to(self):
        return self.__to

    def get_subject(self):
        return self.__subject

    def get_msg(self):
        return self.__msg

    def get_id(self):
        return self.__id


class User:
    '''
    User class
    It mission is to store a user in a proper way

    Attributes:
        __name : username
        __password : user password
        __rsa_publ_key_file : filename where user public key is stored
        __g : generator of Diffie-Hellman's handshake
        __p : prime of Diffie-Hellman's handshake
        __A : g^a (mop p) Diffie-Hellman's handshake
        __b : b generated to create K (Diffie-Hellan's symm key)
        __messages : array of Messages sent to this user
        __nmessages : number of stored messages

    Typical use:
        usr = User("Jack", "ndjkafjk", generator, prime, A, b)
    '''

    def __init__(self, name, password, rsa_publ_key, g, p, A, b):
        self.__name = name
        self.__password = password
        path = RESOURCES_FOLDER+SERVER_CLIENTS_KEYS_FOLDER+name+"_"+PUBL_KEY_FILE
        file_out = open(path, "wb")
        file_out.write(rsa_publ_key.encode())
        file_out.close()
        self.__rsa_publ_key_file = path
        self.__g = g
        self.__p = p
        self.__A = A
        self.__b = b
        self.__messages = []
        self.__nmessages = 0

    def get_name(self):
        return self.__name

    def get_password(self):
        return self.__password

    def get_rsa_publ_key_file(self):
        return self.__rsa_publ_key_file

    def get_g(self):
        return self.__g

    def get_p(self):
        return self.__p

    def get_A(self):
        return self.__A

    def get_b(self):
        return self.__b

    def add_message(self, from_name, subject, msg):
        self.__messages.append(Message(from_name, self.__name, subject, msg))
        self.__nmessages += 1

    def get_list_msgs(self):
        if self.__nmessages == 0:
            return "There is no messages"
        msgs = ""
        for msg in self.__messages:
            msgs += "["+str(msg.get_id())+"] - "+msg.get_from()+": "+msg.get_subject()+"\n"
        return msgs

    def get_msg(self, msg_id):
        for msg in self.__messages:
            if msg.get_id() == int(msg_id):
                m = "From: "+msg.get_from()+"\n"
                m += "To: "+msg.get_to()+"\n"
                m += "Subject: "+msg.get_subject()+"\n"
                m += "Message: "+msg.get_msg()+"\n"
                return m
        return "There is no message with ID="+str(msg_id)


class UserDatabase:
    '''
    UserDatabase class
    It mission is to store a certain amount of users

    Attributes:
        __max_users : maximum number of registered users
        __users : array of registered users
        __nusers : number of registered users

    Typical use:
        db = UserDatabase(max_users=1000)
        db.insert_user("Jack", "dnasjkfbas")
        db.authenticate_user("Jack", "dnasjkfbas")
        db.get_user_rsa_publ_key_file("Jack")
        db.send_message("Jack", "Peter", "subject1", "This is a message")
        db.read_msg("Peter", 0) # 0 := message id
        db.delete_user("Jack", "dnasjkfbas")
    '''

    def __init__(self, max_users=100):
        self.__max_users = max_users
        self.__users = []
        self.__nusers = 0

    def insert_user(self, name, password, publ_key, g, p, A, b):
        if g==None or p==None or A==None or b==None:
            raise Exception("There is no trace of Diffie-Hellman handshake")
        for user in self.__users:
            if user.get_name() == name:
                raise Exception("There is already an user registered with this name")
        self.__users.append(User(name, password, publ_key, g, p, A, b))
        self.__nusers += 1

    def delete_user(self, name, password):
        for i in range(self.__nusers):
            if self.__users[i].get_name() == name:
                if self.__users[i].get_password() == password:
                    self.__users.pop(i)
                    self.__nusers -= 1
        raise Exception("This user does not exist")

    def authenticate_user(self, name, password):
        for user in self.__users:
            if user.get_name() == name:
                if user.get_password() == password:
                    return
        raise Exception("Incorrect username or password")

    def get_user_rsa_publ_key_file(self, username):
        for user in self.__users:
            if user.get_name() == username:
                return user.get_rsa_publ_key_file()
        return USR_NOT_FOUND_DB_MSG

    def get_list_users(self):
        msg = ""
        for user in self.__users:
            msg += user.get_name() + "\n"
        return msg

    def send_message(self, from_name, to_name, subject, msg):
        for user in self.__users:
            if user.get_name() == to_name:
                user.add_message(from_name, subject, msg)
                return "Message delivered successfully to \'"+to_name+"\'"
        return "User \'"+to_name+"\' not found"

    def list_messages(self, username):
        for user in self.__users:
            if user.get_name() == username:
                return user.get_list_msgs()
        return USR_NOT_FOUND_DB_MSG

    def read_msg(self, username, msg_id):
        for user in self.__users:
            if user.get_name() == username:
                return user.get_msg(msg_id)
        return USR_NOT_FOUND_DB_MSG



class TermailServer:
    '''
    TermailServer class
    Created the Termail Server to handle its functionality

    Attributes:
        server_ip : ip where the server is binded
        server_port : port where the server is binded
        verbose : whether to print progress messages to stdout.
        listen_size : maximum number of clients waiting to connect
        server_skt : server's socket
        max_clients : maximum number of connections from clients
        connected_users : counter of the connected users
        total_users : total number of users that have been connected
        recv_size : maximum number of bytes that can be received in a single connection
        user_db : users' database
        log_file : server log file to register activity
        privKF : server RSA private key file
        publKF : server RSA public key file
        priv_key : server RSA private key
        publ_key : server RSA public key

    Typical use:
        Shown at if __name__ == '__main__':
    '''

    def __init__(self, server_ip, server_port, verbose, listen_size=20,
                 max_clients=5, recv_size=4096, log_file=None):
        # Server ip
        self.server_ip = server_ip
        # Server port
        self.server_port = server_port
        # Verbosity
        self.verbose = verbose
        # Server listening size
        self.listen_size = listen_size
        # Server socket
        self.server_skt = -1
        # Server maximum client limit
        self.max_clients = max_clients
        # Server connected users counter
        self.connected_users = 0
        # Server total users counter
        self.total_users = 0
        # Maximum length of messages
        self.recv_size = recv_size
        # User database
        self.user_db = UserDatabase()
        # Server log file to register activity
        self.log_file = log_file
        # Server private and public RSA keys
        self.privKF = RESOURCES_FOLDER+SERVER_KEYS_FOLDER+PRIV_KEY_FILE
        self.publKF = RESOURCES_FOLDER+SERVER_KEYS_FOLDER+PUBL_KEY_FILE
        self.priv_key, self.publ_key = generate_RSA_keys(self.privKF, self.publKF)



    def init_server(self):
        # Opening socket internet/TCP
        self.server_skt = skt.socket(skt.AF_INET, skt.SOCK_STREAM)
        # Reusing the used address after closing
        self.server_skt.setsockopt(skt.SOL_SOCKET, skt.SO_REUSEADDR, 1)
        # Preparing ip and port to recieve connections
        self.server_skt.bind((self.server_ip, self.server_port))
        # Listening connections
        self.server_skt.listen(self.listen_size)


    def close_server(self):
        # Closing server socket
        self.server_skt.close()


    def server_log_msg(self, msg):
        if self.log_file != None:
            f = open(self.log_file, "a")
            f.write(msg)
            f.close()
        else:
            print(msg)


    def accept_connection(self):
        # Accepting client connection
        client_skt, client_addr = self.server_skt.accept()
        return client_skt, client_addr


    def available(self):
        if self.connected_users < self.max_clients:
            return 1
        return 0


    def register_user(self, name, password, publ_key, g, p, A, b):
        try:
            self.user_db.insert_user(name, password, publ_key, g, p, A, b)
        except Exception as err:
            raise Exception(str(err))


    def sign_in_user(self, name, password):
        try:
            self.user_db.authenticate_user(name, password)
        except Exception as err:
            raise Exception(str(err))

    def list_users(self):
        return self.user_db.get_list_users()

    def send_msg(self, from_name, to_name, subject, msg):
        return self.user_db.send_message(from_name, to_name, subject, msg)

    def list_messages(self, username):
        return self.user_db.list_messages(username)

    def read_msg(self, username, msg_id):
        return self.user_db.read_msg(username, msg_id)


    def client_handler(self, client_skt, client_addr):
        self.total_users += 1
        self.connected_users += 1

        logged_user = None
        generator = None
        prime = None
        A = None
        b = None
        B = None
        K = None
        while 1:
            try:
                command_bytes = client_skt.recv(self.recv_size)
                try:
                    command_str = command_bytes.decode()
                    if len(command_str) == 0: # Client closed
                        self.server_log_msg("User has forced the disconnection")
                        break
                    args = command_str.split()
                    # Client asking for server's public key
                    if args[CMD] == "SERVER_PUBLIC_KEY":
                        msg = self.priv_key
                        client_skt.send(msg)
                        continue
                    elif args[CMD] == "SETUP_DH":
                        # Diffie-Hellman handshake
                        prime = int(args[MODULO])
                        generator = int(args[GENERATOR])
                        A = int(args[A_IND])
                        b = get_randint_range(1, prime-1)
                        B = pow(generator, b, prime)
                        msg = str(B)
                        # Sending B (g^b) to client
                        client_skt.send(msg.encode())
                        K = pow(A, b, prime)
                        # Verbosity
                        if self.verbose:
                            print(">>> Received prime (p): ", prime)
                            print(">>> Received generator (g): ", generator)
                            print(">>> Received A (g^a): ", A)
                            print(">>> Calculated b (random int between 1 and p-1): ", b)
                            print(">>> Calculated B (g^b): ", B)
                            print(">>> K (shared key): ", K)
                            print("")
                        continue
                    else:
                        msg = "Command \'"+args[CMD]+"\' not supported"
                        client_skt.send(msg.encode())
                except UnicodeDecodeError:
                    # This exception is raised when the command comes encrypted
                    pass
                # Decrypting command
                auxK = str(K).encode()
                if logged_user == None:
                    # Command for registration or sign in
                    # If it is REGISTER cmd, signature is not checked
                    # If it is SIGN_IN, signature is checked later
                    decrypted_cmd, signature = decrypt_command(command_bytes, auxK, verbose=self.verbose)
                else:
                    # Rest of commands
                    decrypted_cmd, signature = decrypt_command(command_bytes, auxK, verbose=self.verbose)
                    publKF = self.user_db.get_user_rsa_publ_key_file(logged_user)
                    try:
                        verify_digital_sign(decrypted_cmd, signature, publKF, verbose=self.verbose)
                    except Exception as err:
                        msg = "Invalid signature: "+str(err)
                        client_skt.send(msg.encode())
                        continue
                command_str = decrypted_cmd.decode()
                args = command_str.split()
                # Registration command
                if args[CMD] == 'REGISTER':
                    try:
                        rsa_publ_key = parse_RSA_key(args, PK)
                        self.register_user(args[USERNAME], args[PASSW], rsa_publ_key, generator, prime, A, b)
                    except Exception as err:
                        msg = "Unable to register: "+str(err)
                        cipher_msg = encrypt_command(msg.encode(), auxK, self.privKF, verbose=self.verbose)
                        client_skt.send(cipher_msg)
                        continue
                    msg = "Registration of user \'"+args[USERNAME]+"\' completed"
                    self.server_log_msg(msg)
                    logged_user = args[USERNAME]
                    cipher_msg = encrypt_command(msg.encode(), auxK, self.privKF, verbose=self.verbose)
                    client_skt.send(cipher_msg)
                # Sign in command
                elif args[CMD] == 'SIGN_IN':
                    publKF = self.user_db.get_user_rsa_publ_key_file(args[USERNAME])
                    if publKF == USR_NOT_FOUND_DB_MSG:
                        msg = "Unable to sign in as \'"+args[USERNAME]+"\': "+USR_NOT_FOUND_DB_MSG
                        cipher_msg = encrypt_command(msg.encode(), auxK, self.privKF, verbose=self.verbose)
                        client_skt.send(cipher_msg)
                        continue
                    try:

                        verify_digital_sign(decrypted_cmd, signature, publKF, verbose=self.verbose)
                        self.sign_in_user(args[USERNAME], args[PASSW])
                    except Exception as err:
                        msg = "Unable to sign in: "+str(err)
                        cipher_msg = encrypt_command(msg.encode(), auxK, self.privKF, verbose=self.verbose)
                        client_skt.send(cipher_msg)
                        continue
                    msg = "Sign in as \'"+args[USERNAME]+"\' successfully"
                    logged_user = args[USERNAME]
                    self.server_log_msg("Client \'"+logged_user+"\' has just signed in")
                    cipher_msg = encrypt_command(msg.encode(), auxK, self.privKF, verbose=self.verbose)
                    client_skt.send(cipher_msg)
                # Sign out command
                elif args[CMD] == 'SIGN_OUT':
                    self.server_log_msg("Client \'"+logged_user+"\' has just signed out")
                    client_skt.close()
                    self.connected_users -= 1
                    logged_user = None
                    return
                # List users command
                elif args[CMD] == 'LIST_USERS':
                    msg = self.list_users()
                    cipher_msg = encrypt_command(msg.encode(), auxK, self.privKF, verbose=self.verbose)
                    client_skt.send(cipher_msg)
                # Sending message
                elif args[CMD] == 'SEND_MSG':
                    message = prepare_msg(args)
                    msg = self.send_msg(logged_user, args[USERNAME], args[SUBJECT], message)
                    cipher_msg = encrypt_command(msg.encode(), auxK, self.privKF, verbose=self.verbose)
                    client_skt.send(cipher_msg)
                # User asked for his received messages
                elif args[CMD] == 'LIST_MSGS':
                    msg = self.list_messages(logged_user)
                    cipher_msg = encrypt_command(msg.encode(), auxK, self.privKF, verbose=self.verbose)
                    client_skt.send(cipher_msg)
                # User asked to read a message with a given ID
                elif args[CMD] == 'READ_MSG':
                    msg = self.read_msg(logged_user, args[MSG_ID])
                    cipher_msg = encrypt_command(msg.encode(), auxK, self.privKF, verbose=self.verbose)
                    client_skt.send(cipher_msg)
                # Command does not match
                else:
                    msg = "Command \'"+args[CMD]+"\' not supported"
                    cipher_msg = encrypt_command(msg.encode(), auxK, self.privKF, verbose=self.verbose)
                    client_skt.send(cipher_msg)
            except skt.error as err:
                self.server_log_msg("Socket error: "+str(err))
        client_skt.close()
        self.connected_users -= 1



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

    IP = 0
    PORT = 1
    SLEEP_TIME = 5

    try:
        termail = TermailServer(server_ip, server_port, verbose)
    except Exception as err:
        termail.server_log_msg("INIT ERROR: "+str(err))
        exit()
    termail.server_log_msg("Server created and RSA keys have just been generated")

    termail.server_log_msg("Opening server sockets")
    try:
        termail.init_server()
    except skt.error as err:
        termail.server_log_msg("Unable to initialize the server: "+str(err))
        exit()
    termail.server_log_msg("Listening in " + server_ip + ":" + str(server_port))

    # Accepting connections
    while(True):
        # Checking the server is available to accept another client
        if not termail.available():
            termail.server_log_msg("Maximum client number reached, try to connect later")
            time.sleep(SLEEP_TIME)
            continue
        try:
            client_skt, client_addr = termail.accept_connection()
            # client_addr[0] = client_ip , client_addr[1] = client_port
            termail.server_log_msg("Establish connection from " + client_addr[IP] + ":" + str(client_addr[PORT]))

            client_handler = thr.Thread(
                target = termail.client_handler,
                args = (client_skt,client_addr,)
            )
            client_handler.start()

        except skt.error as err:
            termail.server_log_msg("Socket error: "+str(err))
            termail.close_server()
            break
        except KeyboardInterrupt:
            termail.server_log_msg("Closing Termail server")
            termail.close_server()
            break
