from termail_util import *
import socket as skt
import threading as thr
import time

ERROR = -1
SUCCESS = 0
CMD = 0
USERNAME = 1
PASSW = 2
SUBJECT = 2
MSG = 3
MSG_ID = 1

total_msgs = 0
class Message:
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

    def __init__(self, name, password):
        self.__name = name
        self.__password = password
        self.__messages = []
        self.__nmessages = 0

    def get_name(self):
        return self.__name

    def get_password(self):
        return self.__password

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
            ######################################################
            print(str(msg.get_id()) + " : "+ msg.get_msg() +"\n")
            if msg.get_id() == int(msg_id):
                m = "From: "+msg.get_from()+"\n"
                m += "To: "+msg.get_to()+"\n"
                m += "Subject: "+msg.get_subject()+"\n"
                m += "Message: "+msg.get_msg()+"\n"
                return m
        return "There is no message with ID="+str(msg_id)


class UserDatabase:

    def __init__(self, max_users=100):
        self.__max_users = max_users
        self.__users = []
        self.__nusers = 0

    def insert_user(self, name, password):
        for user in self.__users:
            if user.get_name() == name:
                raise Exception("There is already an user registered with this name")
        self.__users.append(User(name, password))
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
        return "User not found in the database"

    def read_msg(self, username, msg_id):
        for user in self.__users:
            if user.get_name() == username:
                return user.get_msg(msg_id)
        return "User not found in the database"



class TermailServer:

    def __init__(self, server_ip, server_port, listen_size=20, max_clients=5,
                 recv_size=1024, log_file=None):
        # Server ip
        self.server_ip = server_ip
        # Server port
        self.server_port = server_port
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


    def register_user(self, name, password):
        try:
            self.user_db.insert_user(name, password)
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
        while 1:
            try:
                command_bytes = client_skt.recv(self.recv_size)
                command_str = command_bytes.decode()
                if len(command_str) == 0: # Client closed
                    self.server_log_msg("User \'+"+logged_user+"\' has forced the disconnection")
                    break
                args = command_str.split()
                # Registration command
                if args[CMD] == 'REGISTER':
                    try:
                        self.register_user(args[USERNAME], args[PASSW])
                    except Exception as err:
                        msg = "Unable to register: "+str(err)
                        client_skt.send(msg.encode())
                    msg = "Registration of user \'"+args[USERNAME]+"\' completed"
                    self.server_log_msg(msg)
                    logged_user = args[USERNAME]
                    client_skt.send(msg.encode())
                # Sign in command
                elif args[CMD] == 'SIGN_IN':
                    try:
                        self.sign_in_user(args[USERNAME], args[PASSW])
                    except Exception as err:
                        msg = "Unable to sign in: "+str(err)
                        client_skt.send(msg.encode())
                    msg = "Sign in as \'"+args[USERNAME]+"\' successfully"
                    logged_user = args[USERNAME]
                    self.server_log_msg("Client \'"+logged_user+"\' has just signed in")
                    client_skt.send(msg.encode())
                # Sign out command
                elif args[CMD] == 'SIGN_OUT':
                    self.server_log_msg("Client \'"+logged_user+"\' has just signed out")
                    client_skt.close()
                    self.connected_users -= 1
                    return
                # List users command
                elif args[CMD] == 'LIST_USERS':
                    msg = self.list_users()
                    client_skt.send(msg.encode())
                # Sending message
                elif args[CMD] == 'SEND_MSG':
                    message = prepare_msg(args)
                    msg = self.send_msg(logged_user, args[USERNAME], args[SUBJECT], message)
                    client_skt.send(msg.encode())
                # User asked for his received messages
                elif args[CMD] == 'LIST_MSGS':
                    msg = self.list_messages(logged_user)
                    client_skt.send(msg.encode())
                # User asked to read a message with a given ID
                elif args[CMD] == 'READ_MSG':
                    msg = self.read_msg(logged_user, args[MSG_ID])
                    client_skt.send(msg.encode())
                # Command does not match
                else:
                    msg = "Command \'"+args[CMD]+"\' not supported"
                    client_skt.send(msg.encode())
            except skt.error as err:
                self.server_log_msg("Socket error: "+str(err))
                client_skt.close()
                self.connected_users -= 1
        client_skt.close()
        self.connected_users -= 1



if __name__ == "__main__":
    server_ip = '127.0.0.1'
    server_port = 5005
    IP = 0
    PORT = 1
    SLEEP_TIME = 5

    termail = TermailServer(server_ip, server_port)

    try:
        termail.init_server()
    except skt.error as err:
        termail.server_log_msg("Unable to initialize the server: "+str(err))
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
            termail.server_log_msg("Establish connection from" + client_addr[IP] + ":" + str(client_addr[PORT]))

            client_handler = thr.Thread(
                target = termail.client_handler,
                args = (client_skt,client_addr,)
            )
            client_handler.start()

        except skt.error as err:
            termail.server_log_msg("Socket error: "+str(err))
        except KeyboardInterrupt:
            termail.server_log_msg("Closing Termail server")
            termail.close_server()
            exit()
