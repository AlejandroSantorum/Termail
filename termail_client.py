import socket as skt

ERROR = -1
SUCESS = 0
REGISTER = 1
SIGN_IN = 2
EXIT = 3

class TermailClient:

    def __init__(self, server_ip, server_port, recv_size=1024):
        self.server_ip = server_ip
        self.server_port = server_port
        self.client_skt = -1
        self.recv_size = recv_size


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
        # Preparing command
        msg = "REGISTER "+name+" "+password
        # Sending message to server
        self.client_skt.send(msg.encode())
        # Waiting for response
        server_answer = self.client_skt.recv(self.recv_size)
        print(server_answer.decode())


    def sign_in(self):
        name = input("Introduce nickname: ")
        password = input("Introduce password: ")
        try:
            self._open_socket()
        except skt.error as err:
            raise err
        # Preparing command
        msg = "SIGN_IN "+name+" "+password
        # Sending message to server
        self.client_skt.send(msg.encode())
        # Waiting for response
        server_answer = self.client_skt.recv(self.recv_size)
        print(server_answer.decode())

    def print_help(self):
        print("Available commands:")
        print("· HELP\n\t-> shows all commands")
        print("· SIGN_OUT\n\t-> closes the connection with the Termail server")
        print("· LIST_USERS\n\t-> sends to Termail server a request to get all the connected users")


    def sign_out(self):
        self.client_skt.close()


if __name__ == "__main__":
    server_ip = '127.0.0.1'
    server_port = 5005

    termail = TermailClient(server_ip, server_port)
    # Start panel: register, sign in or exit
    mode = termail.login()
    try:
        if mode == REGISTER:
            termail.register()
        elif mode == SIGN_IN:
            termail.sign_in()
        elif mode == EXIT:
            print("Exit successfully")
            exit()
        else:
            print("Error: Login mode failed")
    except skt.error as err:
        print("Socket error: "+str(err))

    # Once registered or signed in, you can send several commands
    while 1:
        command = input("Introduce command: ")
        cmd_items = command.split()
        if cmd_items[0] == "HELP":
            termail.print_help()
        elif cmd_items[0] == "SIGN_OUT":
            termail.sign_out()
            break
        #elif cmd_items[0] == "TEST_CONN":
        #    termail.test_connection()
        else:
            print("Invalid command. Use HELP command if needed")
