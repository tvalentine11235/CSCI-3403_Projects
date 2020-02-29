"""
    add_user.py - Stores a new username along with salt/password

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    The solution contains the same number of lines (plus imports)
"""

import hashlib, uuid

user = input("Enter a username: ")
password = input("Enter a password 8-64 characters long: ")
passChk = False
while passChk == False:
    if(len(password) > 8 and len(password) < 64):
        passChk = True
    else:
        password = input("Password is too long or too short. Enter a password 8-64 characters long: ")

# TODO: Create a salt and hash the password
salt = uuid.uuid4().hex
hashed_password = hashlib.sha512((password + salt).encode('utf-8')).hexdigest()

try:
    reading = open("passfile.txt", 'r')
    for line in reading.read().split('\n'):
        if line.split('\t')[0] == user:
            print("User already exists!")
            exit(1)
    reading.close()
except FileNotFoundError:
    pass

with open("passfile.txt", 'a+') as writer:
    writer.write("{0}\t{1}\t{2}\n".format(user, salt, hashed_password))
    print("User successfully added!")
