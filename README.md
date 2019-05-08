# Termail
## Communication Networks project for second semester, called Termail (terminal mail)

## Description
Project that implements a mail service with the goal of understanding Diffie-Hellman key exchange protocol. It is written in Python and it can be run on any Unix system, with the only requirement of having *Pycryptodome* libray installed.

## Execution
The server script called **termail_server.py** is suppossed to be running in a concrete IP and port. Then any client script, **termail_client.py**, can connect to it and execute the following commands after registering/signing in the server:

*HELP*: It shows all the possible commands

*LIST_USERS*: It sends the Termail server a request to get the users' list and show it on screen.

*SEND_MSG <name> <msg_subject> <msg_text>*: It sends a message to the user with nickname 'name', with subject 'msg_subject'.
  
*LIST_MSGS*: It sends the Termail server a request to get all the received messages.

*READ_MSG <msg_id>*:  It requests the Termail server the message with ID='msg_id'.

*SIGN_OUT*: It closes the connection with the server and terminates the process.


