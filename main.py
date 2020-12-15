from app import app, mongo, User
from bson.json_util import dumps
from bson.objectid import ObjectId
from flask import jsonify, request
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt import JWT, jwt_required, current_identity
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    jwt_refresh_token_required,
    get_jwt_identity,
    get_raw_jwt
)


@app.route('/signup', methods=['POST'])
def add_user():
    _json = request.json
    _username = _json['username']
    _email = _json['email']
    _password = _json['password']
    # validate the received values
    user_username = mongo.db.user.find_one({'username': _username})
    if user_username:
        return not_found('username exists !')
    user_email = mongo.db.user.find_one({'email': _email})
    if user_email:
        return not_found('Email exists')
    try:
        # do not save password as a plain text
        _hashed_password = generate_password_hash(_password)
        # save details
        _id = mongo.db.user.insert(
            {'username': _username, 'email': _email, 'password': _hashed_password, 'role': 'ROLE_USER'})
        resp = jsonify('User added successfully! ' + str(_id))
        resp.status_code = 200
        return resp
    except:
        return not_found('signup failure !')


@app.route('/signin', methods=['POST'])
def login():
    _json = request.json
    _username = _json['username']
    _password = _json['password']
    _userCurrent = mongo.db.user.find_one({'username': _username})
    if check_password_hash(_userCurrent['password'], _password):
        access_token = create_access_token(identity=_username)
        return {
            'user': {
                'id': str(_userCurrent['_id']),
                'username': _userCurrent['username'],
                'password': _userCurrent['password'],
                'email': _userCurrent['email'],
                'roles': [_userCurrent['role']]
            },
            'access_token': access_token
        }
    else:
        return {'message': "Wrong credentials"}


def authenticate(username, password):
    if username and password:
        _user = mongo.db.user.find_one({'username': username})
        if check_password_hash(_user['password'], password):
            return User(str(_user['_id']), _user['username'])
        else:
            return "incorrect username or password"
    return "incorrect username or password"


def identity(payload):
    if payload['identity']:
        _user = mongo.db.user.find_one({'_id': ObjectId(payload['identity'])})
        if _user:
            return User(str(_user['_id']), _user['name'])
        else:
            return None
    else:
        return None


@app.route('/users')
@jwt_required
def users():
    _users = mongo.db.user.find()
    resp = dumps(_users)

    return resp


@app.route('/account')
@jwt_required
# @roles_required('ADMIN')
def accounts():
    _accounts = mongo.db.accounts.find().limit(100)
    resp = dumps(_accounts)
    return resp


@app.route('/user/<id>')
@jwt_required
def user(id):
    _user = mongo.db.user.find_one({'_id': ObjectId(id)})
    resp = dumps(_user)
    return resp


@app.route('/account/<id>')
@jwt_required
def account(id):
    _account = mongo.db.accounts.find_one({'_id': ObjectId(id)})
    resp = dumps(_account)
    return resp


@app.route('/update', methods=['PUT'])
@jwt_required
def update_user():
    _json = request.json
    _id = _json['_id']
    _name = _json['name']
    _email = _json['email']
    _password = _json['pwd']
    # validate the received values
    if _name and _email and _password and _id and request.method == 'PUT':
        # do not save password as a plain text
        _hashed_password = generate_password_hash(_password)
        # save edits
        mongo.db.user.update_one({'_id': ObjectId(_id['$oid']) if '$oid' in _id else ObjectId(_id)},
                                 {'$set': {'name': _name, 'email': _email, 'pwd': _hashed_password}})
        resp = jsonify('User updated successfully!')
        resp.status_code = 200
        return resp
    else:
        return not_found()


@app.route('/account', methods=['PUT', 'POST'])
@jwt_required
def update_account():
    _json = request.json
    _account_number = int(_json['account_number'])
    _balance = int(_json['balance'])
    _firstname = _json['firstname']
    _lastname = _json['lastname']
    _age = int(_json['age'])
    _gender = _json['gender']
    _address = _json['address']
    _employer = _json['employer']
    _email = _json['email']
    _city = _json['city']
    _state = _json['state']
    # validate the received values
    if request.method == 'PUT':
        _id = _json['_id']

        # save edits
        mongo.db.accounts.update_one({'_id': ObjectId(_id['$oid']) if '$oid' in _id else ObjectId(_id)},
                                     {'$set': {'account_number': _account_number, 'balance': _balance,
                                               'firstname': _firstname,
                                               'lastname': _lastname, 'age': _age, 'gender': _gender,
                                               'address': _address, 'employer': _employer,
                                               'email': _email, 'city': _city, 'state': _state
                                               }})
        resp = jsonify('Account updated successfully!')
        resp.status_code = 200
        return resp
    elif request.method == 'POST':
        account_account_number = mongo.db.accounts.find_one({'account_number': _account_number})
        if account_account_number:
            return {'message': 'account number already exists !'}
        else:
            _id = mongo.db.accounts.insert_one({'account_number': _account_number, 'balance': _balance,
                                                'firstname': _firstname,
                                                'lastname': _lastname, 'age': _age, 'gender': _gender,
                                                'address': _address, 'employer': _employer,
                                                'email': _email, 'city': _city, 'state': _state})
            resp = jsonify('Account added successfully! ' + str(_id))
            resp.status_code = 200
            return resp
    else:
        return not_found()


@app.route('/delete/<id>', methods=['DELETE'])
@jwt_required
def delete_user(id):
    mongo.db.user.delete_one({'_id': ObjectId(id)})
    resp = jsonify('User deleted successfully!')
    resp.status_code = 200
    return resp


@app.route('/account/<id>', methods=['DELETE'])
@jwt_required
def delete_account(id):
    mongo.db.accounts.delete_one({'_id': ObjectId(id)})
    resp = jsonify('Account deleted successfully!')
    resp.status_code = 200
    return resp


@app.errorhandler(404)
def not_found(msg):
    message = {
        'status': 404,
        'message': msg
    }
    resp = jsonify(message)
    resp.status_code = 404

    return resp


@app.route('/search_account', methods=['POST'])
@jwt_required
def search_account():
    _json = request.json
    search_dict = {}
    if _json['account_number']:
        search_dict['account_number'] = {"$gt": int(_json['account_number'])}
    if _json['balance']:
        search_dict['balance'] = {"$gt": int(_json['balance'])}
    if _json['firstname']:
        search_dict['firstname'] = {'$regex': _json['firstname']}
    if _json['lastname']:
        search_dict['lastname'] = {'$regex': _json['lastname']}
    if _json['age']:
        search_dict['age'] = {"$gt": int(_json['age'])}
    if _json['gender']:
        search_dict['gender'] = _json['gender']
    if _json['address']:
        search_dict['address'] = {'$regex': _json['address']}
    if _json['employer']:
        search_dict['employer'] = {'$regex': _json['employer']}
    if _json['email']:
        search_dict['email'] = {'$regex': _json['email']}
    if _json['city']:
        search_dict['city'] = {'$regex': _json['city']}
    if _json['state']:
        search_dict['state'] = {'$regex': _json['state']}
        # limit = _json['limit']
    page = _json['page']
    # last_id = _json['last_id']
    # if (page == 1):
    #     search_dict['_id'] = {'$gt': ObjectId('000000000000000000000000')}
    # else:
    #     search_dict['_id'] = {'$gt': ObjectId(last_id)}
    if page == 1:
        total_record = mongo.db.accounts.find(search_dict).count()
    else:
        total_record = 0
    _accounts = mongo.db.accounts.find(search_dict).sort([('account_number', 1)]).skip(100 * (page - 1)).limit(100)
    # resp = dumps(_accounts)
    resp = {
        'accounts': dumps(_accounts),
        'total_record': total_record
    }

    return resp


jwt = JWT(app, authenticate, identity)

if __name__ == "__main__":
    app.run()
