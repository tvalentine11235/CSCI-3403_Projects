"""
    server.py - host an SSL server that checks passwords
    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 140
        (Feel free to use more or less, this
        is provided as a sanity check)
    Put your team members' names:
"""

import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import hashlib, uuid

host = "localhost"
port = 10001


# A helper function. It may come in handy when performing symmetric encryption
def pad_message(message):
    return message + " " * ((16 - len(message)) % 16)


# Write a function that decrypts a message using the server's private key
def decrypt_key(session_key):
    # TODO: Implement this function
    f = open('./Keys')
    deKey = RSA.importKey(f.read())
    message = deKey.decrypt(session_key)
    return message


# Write a function that decrypts a message using the session key
def decrypt_message(client_message, session_key):
    # TODO: Implement this function
    cipher = AES.new(session_key)
    plaintext_message = cipher.decrypt(client_message)
    return plaintext_message

# Encrypt a message using the session key
def encrypt_message(message, session_key):
    # TODO: Implement this function
    paddedMessage = pad_message(message)
    cipher = AES.new(session_key)
    encryptedMessage = cipher.encrypt(paddedMessage)
    return encryptedMessage


# Receive 1024 bytes from the client
def receive_message(connection):
    return connection.recv(1024)


# Sends message to client
def send_message(connection, data):
    if not data:
        print("Can't send empty string")
        return
    if type(data) != bytes:
        data = data.encode()
    connection.sendall(data)


# A function that reads in the password file, salts and hashes the password, and
# checks the stored hash of the password to see if they are equal. It returns
# True if they are and False if they aren't. The delimiters are newlines and tabs
def verify_hash(user, password):
    try:
        reader = open("passfile.txt", 'r')
        for line in reader.read().split('\n'):
            line = line.split("\t")
            if line[0] == user:
                # TODO: Generate the hashed password
                # hashed_password =
                return hashed_password == line[2]
        reader.close()
    except FileNotFoundError:
        return False
    return False


def main():
    # Set up network connection listener
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (host, port)
    print('starting up on {} port {}'.format(*server_address))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(server_address)
    sock.listen(1)

    try:
        while True:
            # Wait for a connection
            print('waiting for a connection')
            connection, client_address = sock.accept()
            try:
                print('connection from', client_address)

                # Receive encrypted key from client
                encrypted_key = receive_message(connection)

                # Send okay back to client
                send_message(connection, "okay")

                # Decrypt key from client
                plaintext_key = decrypt_key(encrypted_key)

                # Receive encrypted message from client
                ciphertext_message = receive_message(connection)

                # Decrypt message from client
                plaintext_message = decrypt_message(ciphertext_message, plaintext_key)
                plaintext_message = plaintext_message.decode('utf-8')
                new = plaintext_message.split()
                
                # Check that both username and password fields have been populated to avoid seg faults!
                if len(new) is not 2:
                    noauth = encrypt_message("Please Enter Both Username and Password",plaintext_key)
                    print("sending encrypted unauthentic")
                    send_message(connection,noauth)

                # Validate username and password
                else:
                    username = new[0]
                    password = new[1]
                    print('username:', username, 'password:', password)
                    f = open("../passfile.txt",'r')
                    un_salt_pass = []
                    match = False
                    # Each line in f will be a user, salt, and hashed password
                    for line in f:
                        un_salt_pass.append(line.split('\t'))
                    # check usernames and salt+password hash value
                    for user in un_salt_pass:
                        if username == user[0]:
                            enc_pass = hashlib.sha512((password + user[1]).encode('utf-8')).hexdigest()
                            # strip the \n from the end of the saved hashed password 
                            if enc_pass == user[2].rstrip():
                                match = True
                                break
                    if match is True:
                        auth = encrypt_message("User Successfully Authenticated",plaintext_key)
                        print("sending encrypted authentic")
                        send_message(connection,auth)
                    else:
                        noauth = encrypt_message("Invalid Username or Password",plaintext_key)
                        print("sending encrypted unauthentic")
                        send_message(connection,noauth)
            finally:
                # Clean up the connection
                connection.close()
    finally:
        sock.close()


if __name__ in "__main__":
    main()