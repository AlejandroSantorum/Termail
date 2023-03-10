# Termail
## Communication Networks project for second semester, called Termail (terminal mail)

## Description
Project that implements a mail service with the goal of understanding Diffie-Hellman key exchange protocol. It is written in Python and it can be run on any Unix system, with the only requirement of having *Pycryptodome* library installed.

## Execution
The server script called **termail_server.py** is suppossed to be running in a particular IP and port. If none IP and port are provided as input parameters (argv[1] and argv[2]), the server is going to be binded in *Loopback IP 127.0.0.1* and port *5005* by default. Additionally, there exists a optional input parameters, **-v**, that can be selected to activate verbosity and to monitor encryption algorithms. Execution examples:
* *python3 termail_server.py* -> server is opened in 127.0.0.1:5005 with crypto-verbosity deactivated.
* *python3 termail_server.py -v* -> server is opened in 127.0.0.1:5005 with crypto-verbosity activated.
* *python3 termail_server.py 150.100.101.102 8000* -> server is opened in 150.100.101.102:8000 with crypto-verbosity deactivated.
* *python3 termail_server.py 150.100.101.102 8000 -v* -> server is opened in 150.100.101.102:8000 with crypto-verbosity activated.

Then any client script, **termail_client.py** (possible to execute with the same optional arguments than termail_server.py), can connect to it and execute the following commands after registering/signing in the server:

**HELP**: It shows all the possible commands

**LIST_USERS**: It sends the Termail server a request to get the users' list and show it on screen.

**SEND_MSG <name> <msg_subject> <msg_text>**: It sends a message to the user with nickname 'name', with subject 'msg_subject'.
  
**LIST_MSGS**: It sends the Termail server a request to get all the received messages.

**READ_MSG <msg_id>**:  It requests the Termail server the message with ID='msg_id'.

**SIGN_OUT**: It closes the connection with the server and terminates the process.

## Cleaning folders after execution
Both the Termail server and the client create folders to store RSA encryption keys. Two scripts have been added to eliminate this information once we no longer need it: **server_clean.py** and **client_clean.py**.

Feel free to use them but take into account that, once you have removed this information, the server/client should not need any of them because they have just been deleted!


