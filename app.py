from flask import Flask
from flask_restful import Api, Resource
from json import dump

app = Flask(__name__)
api = Api(app)

verification_keys = {"çauâ": "~5~5~"}


def cau_md5(text):
    from base64 import b64encode
    from hashlib import md5

    return md5(b64encode(text.encode('utf-8'))).hexdigest()


class Users:
    def __init__(self):
        self.dictio = {}


users = Users()
write_password = "f3f7c3aa692d203cc779b829c657e08e"


def login_get(_, username, password):
    if username in list(verification_keys.keys()):
        return '{"message": "Account already in use."}', 403
    else:
        if username not in list(users.dictio.keys()):
            return {"message": "Wrong username."}, 403
        if users.dictio[username] == cau_md5(password):
            from random import randint
            ver_key = list(verification_keys.values())[0]
            while ver_key in list(verification_keys.values()):
                ver_key = cau_md5(str(randint(12345678987654321, 98765432123456789)))
            verification_keys[username] = ver_key
            print(verification_keys)
            return {"verification_key": ver_key}
        else:
            return {"message": "Wrong password."}, 403


def logout_get(_, username, verification_key):
    if username in list(verification_keys.keys()) and verification_keys[username] == verification_key:
        verification_keys.pop(username)
        print(verification_keys)
        return {"message": "Successfully log out."}, 200


def add_account_put(_, username, user_pass, add_pass):
    if cau_md5(add_pass) == write_password:
        users.dictio[username] = cau_md5(user_pass)
        return "200", 200
    else:
        return "403", 403


def get_dict_get(_, password):
    if cau_md5(password) == write_password:
        return users.dictio, 200
    else:
        return {"message": "Wrong password."}


def get_logged_ins_get(_, password):
    if cau_md5(password) == write_password:
        return verification_keys, 200
    else:
        return {"message": "Wrong password."}


def verify_get(_, verification_key):
    if verification_key in list(verification_keys.values()):
        return {"do": "nothing"}, 200
    else:
        return {"do": "log_out"}, 403


class LogIn(Resource):
    get = login_get


class LogOut(Resource):
    get = logout_get


class Verify(Resource):
    get = verify_get


class GetDict(Resource):
    get = get_dict_get


class GetLoggedIns(Resource):
    get = get_logged_ins_get


class AddAccount(Resource):
    put = add_account_put


api.add_resource(LogIn, "/login/<string:username>/<string:password>")
api.add_resource(LogOut, "/logout/<string:username>/<string:verification_key>")
api.add_resource(AddAccount, "/add_account/<string:username>/<string:user_pass>/<string:add_pass>")
api.add_resource(GetDict, "/get_dict/<string:password>")
api.add_resource(GetLoggedIns, "/get_logged_ins/<string:password>")
api.add_resource(Verify, "/verify/<string:verification_key>")

if __name__ == "__main__":
    app.run()
