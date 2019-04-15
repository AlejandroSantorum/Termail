import socket as skt

ERROR = -1
SUCCESS = 0
REGISTER = 1
SIGN_IN = 2
EXIT = 3
USERNAME = 1
SUBJECT = 2
MSG = 3

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
        # Opening socket and connecting Termail server
        self._open_socket()
        # Preparing command
        msg = "REGISTER "+name+" "+password
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
            return SUCCESS


    def sign_in(self):
        name = input("Introduce nickname: ")
        password = input("Introduce password: ")
        # Opening socket and connecting Termail server
        self._open_socket()
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
            return SUCCESS


    def print_help(self):
        print("Available commands:")
        print("· HELP\n\t-> shows all commands")
        print("· SIGN_OUT\n\t-> closes the connection with the Termail server")
        print("· LIST_USERS\n\t-> sends to Termail server a request to get the users' list")
        print("· SEND_MSG <Username> <Subject> <Message>\n\t-> sends message to a given user")
        print("· LIST_MSGS\n\t-> lists all your received messages")


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
        except KeyboardInterrupt:
            print("Exiting Termail client")

    # Once registered or signed in, you can send several commands
    while 1:
        try:
            command = input("Introduce command: ")
            cmd_items = command.split()
            if cmd_items[0] == "HELP":
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
                termail.send_msg(cmd_items[USERNAME], cmd_items[SUBJECT], cmd_items[MSG])
            elif cmd_items[0] == "LIST_MSGS":
                termail.list_messages()
            #elif cmd_items[0] == "TEST_CONN":
            #    termail.test_connection()
            else:
                print("Invalid command. Use HELP command if needed")
        except skt.error as err:
            print("Socket error: "+str(err))
        except KeyboardInterrupt:
            print("Exiting Termail client")
            termail.sign_out()
            break
