import socket as skt

ERROR = -1
SUCESS = 0
REGISTER = 1
SIGN_IN = 2
EXIT = 3

class TermailClient:

    def __init__(self, server_ip, server_port):
        self.server_ip = server_ip
        self.server_port = server_port
        self.client_skt = -1


    def login(self):
        while 1:
            try:
                print("Select one option:")
                print("["+str(REGISTER)+"] Register")
                print("["+str(SIGN_IN)+"] Sign in")
                print("["+str(EXIT)+"] Exit")
                mode = int(input())
                if mode > 3 or mode < 1:
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


    def register(self):
        name = input("Introduce nickname to be registered: ")
        while 1:
            password = input("Introduce password: ")
            password2 = input("Reintroduce password again: ")
            if password == password2:
                break
            print("Password does not match. Try again")
        try:
            self._open_socket()
        except skt.error as err:
            raise err


    def sign_in(self):
        name = input("Introduce nickname: ")
        password = input("Introduce password: ")
        try:
            self._open_socket()
        except skt.error as err:
            raise err


if __name__ == "__main__":
    server_ip = '127.0.0.1'
    server_port = 5005

    termail = TermailClient(server_ip, server_port)
    mode = termail.login()
    if mode == REGISTER:
        try:
            termail.register()
        except skt.error as err:
            print("Socket error: "+str(err))
    elif mode == SIGN_IN:
        try:
            termail.sign_in()
        except skt.error as err:
            print("Socket error: "+str(err))
    elif mode == EXIT:
        print("Exit successfully")
        exit()
    else:
        print("Error: Login mode failed")
