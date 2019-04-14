import socket as skt
import threading as thr
import time

ERROR = -1
SUCCESS = 0
CMD = 0
USERNAME = 1
PASSW = 2

class User:
    def __init__(self, name, password):
        self.__name = name
        self.__password = password

    def get_name(self):
        return self.__name

    def get_password(self):
        return self.__password


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

    def delete_user(self, name, password):
        for i in range(self.__nusers):
            if self.__users[i].get_name() == name:
                if self.__users[i].get_password() == password:
                    self.__users.pop(i)
                    return SUCCESS
        raise Exception("This user does not exist")


class TermailServer:

    def __init__(self, server_ip, server_port, listen_size=20, max_clients=5,
                 recv_size=1024):
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


    def client_handler(self, client_skt, client_addr):
        self.total_users += 1
        self.connected_users += 1

        try:
            command_bytes = client_skt.recv(self.recv_size)
            command_str = command_bytes.decode()
            args = command_str.split()
            if args[CMD] == 'REGISTER':
                try:
                    self.register_user(args[USERNAME], args[PASSW])
                except Exception as err:
                    msg = "Unable to register: "+str(err)
                    client_skt.send(msg.encode())
                msg = "Registration of user \'"+args[USERNAME]+"\' completed"
                client_skt.send(msg.encode())
            else:
                msg = "Command \'"+args[CMD]+"\' not supported"
                client_skt.send(msg.encode())
        except skt.error as err:
            print("Socket error: "+str(err))
        finally:
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
        print("Unable to initialize the server: "+str(err))
    print("Listening in " + server_ip + ":" + str(server_port))

    # Accepting connections
    while(True):
        # Checking the server is available to accept another client
        if not termail.available():
            print("Maximum client number reached, try to connect later")
            time.sleep(SLEEP_TIME)
            continue
        try:
            client_skt, client_addr = termail.accept_connection()
            # client_addr[0] = client_ip , client_addr[1] = client_port
            print("Establish connection from" + client_addr[IP] + ":" + str(client_addr[PORT]))

            client_handler = thr.Thread(
                target = termail.client_handler,
                args = (client_skt,client_addr,)
            )
            client_handler.start()

        except skt.error as err:
            print("Socket error: "+str(err))
        except KeyboardInterrupt:
            print("Closing Termail server")
            termail.close_server()
            exit()
