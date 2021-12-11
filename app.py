import datetime
import os
import uuid
from functools import wraps

from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

import jwt

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SECRET_KEY'] = 'birendra-ssecretkey'

# configuring database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'blog.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# initializing  database
db = SQLAlchemy(app)


# creating database models
# creating user
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)


@app.route("/")
def home_page():
    return "its Just an api "


# creating for authentication
@app.route("/login")
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:  # if the user is not authorized. it returns a response.
        return make_response("could not verify", {"error message": "login is required."})
    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response("could not verify", {"error message": "login is required."})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode(
            {'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=10)},
            app.config['SECRET_KEY']) # JWT token generated with the validity time of 10 minutes

        return jsonify({'token': token})

    return make_response('Could not verify', 401, {'WWW-Auth': 'Basic realm="Login required!"'})


# constructing a decorator to check wheather the header contain valid token
def token_check(f):
    @wraps(f)
    def decoretor(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({"error-msg": "Token is not found"})
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({"error-msg": "Token is inval"})

        return f(current_user, *args, *kwargs)

    return decoretor


@app.route("/user", methods=['POST'])
def create_user():
    data = request.get_json()
    password_encoded = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=password_encoded, admin=True)
    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"success-msg": "New user created"})
    except:
        return jsonify({'error-msg': "Error while saving into database"})


@app.route("/user", methods=['GET'])
@token_check
def get_user(current_user):
    user = User.query.filter_by(public_id=current_user.public_id).first()

    if not user:
        return jsonify({"message": "couldnot find user"})

    user_data = {'public_id': user.public_id, 'name': user.name, 'password': user.password, "id": user.id,
                 'admin': user.admin}
    return jsonify({"users": user_data})


@app.route("/user", methods=['PUT'])
@token_check
def update_user_info(current_user):
    if not current_user.admin:
        return jsonify({'message': "you are not permitted to perform this action"})

    user = User.query.filter_by(public_id=current_user.public_id).first()

    if not user:
        return jsonify({'message': 'user not found'})

    data = request.get_json()

    update_password_encoded = generate_password_hash(data['password'], method='sha256')

    try:
        user.admin = True
        user.name = data['name']
        user.password = update_password_encoded
        db.session.commit()
        return jsonify({'message': 'user updated'})

    except:
        return jsonify({'message': 'Error updating user'})


@app.route("/user", methods=['DELETE'])
@token_check
def delete_user(current_user):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=current_user.public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'The user has been deleted!'})


if __name__ == '__main__':
    app.run(debug=True)
