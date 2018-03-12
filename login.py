import json
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import cryptography
import base64


def json_to_dict(file):
    if not os.path.isfile(file):
        return {}
    with open(file) as json_file:
        try:
            return json.load(json_file)
        except OSError:
            return {}


def dict_to_json(dict):
    return json.dumps(dict)


def save_file_json(file, dict):
    with open(file, 'w') as json_file:
        json_file.write(dict_to_json(dict))


def loadData():
    with open("base.json") as json_file:
        return json.load(json_file)

def create_kdf(salt):
    backend = default_backend()
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=backend)
    return kdf

def new_salt():
    salt = os.urandom(16)
    return salt

def valida(senha, key, salt):
    keydes = base64.b64decode(key)
    saltdes = base64.b64decode(salt)
    
    try:
        create_kdf(saltdes).verify(senha,keydes)
        return True
    except cryptography.exceptions.InvalidKey:
        return False


def create(user, senha):

    salt = os.urandom(16)
    kdf = create_kdf(salt)
    salt64 = base64.b64encode(salt)
    chave = base64.b64encode(kdf.derive(senha))
    users = json_to_dict("base.json")
    users[user] = {"password": chave, "salt": salt64}
    save_file_json("base.json", users)

def login(user, senha):
    
    data = loadData()
    
    for keys, value in data.items():
        if keys == user:
            key = value.get('password')
            salt = value.get('salt')
            if valida(senha, key, salt) == True:
                print "-------------------------------"
                print "Welcome back sr : " + user
                print "-------------------------------"
                return
    print "-----------------------------------------"
    print "Alguma coisa saiu errado, tente novamente"
    print "-----------------------------------------"



def main():

    chose = raw_input("Sign in 0 , sign up 1 = ")
    

    if chose == "0":
        print "--------------------------------"
        print "Insira os dados para fazer login"
        print "--------------------------------"
        user = raw_input("User: ")
        senha = raw_input("Password: ")
        print "\n ---- loading ---- "
        login(user, senha)

    else:
        print "------------------------------------"
        print "Insira os dados para criar uma conta"
        print "------------------------------------"
        print "\n loading \n"
        user = raw_input("User: ")
        senha = raw_input("Password: ")
        create(user, senha)


if __name__ == "__main__":
    main()