#!/usr/bin/env python
import os
from time import time
from flask import Flask, abort, request, jsonify, g, url_for, make_response, session, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth
import jwt
from itsdangerous import Serializer
from werkzeug.security import generate_password_hash, check_password_hash

# initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = 'the quick brown fox jumps over the lazy dog'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True

# extensions
db = SQLAlchemy(app)
auth = HTTPTokenAuth("JWT")


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True)
    password_hash = db.Column(db.String(64))

    # 明文密码（只读）
    @property
    def hash_password(self):
        raise AttributeError('不可读')

    # 写入密码，同时计算hash值，保存到模型中
    @hash_password.setter
    def hash_password(self, password):
        self.password_hash = generate_password_hash(password)

    # 检查密码是否正确
    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_auth_token(self, expires_in=600):
        return jwt.encode(
            {'id': self.id, 'exp': time() + expires_in},
            app.config['SECRET_KEY'], algorithm='HS256')

@auth.verify_token
def verify_auth_token(token):
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'],
                          algorithms=['HS256'])
    except:
        return
    return User.query.get(data['id'])



@app.route('/api/login',methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        abort(400)    # missing arguments
    user:User = User.query.filter_by(username=username).first()
    if user is None:
        return make_response(jsonify({'error': 'unauthorized', 'message': '用户名不存在'}), 403)
    if user.verify_password(password):
        g.current_user = user
        token = user.generate_auth_token(15 * 60)
        # session.permanent = True
        session['username'] = user.username
        session['JWT_token'] = token
        session['JWT_token_expiry'] = int(time()) + 15 * 60
        return make_response(jsonify({
            'username': user.username,
            'token': token,
            'expiration': 15 * 60,
            # 'wizard': wizard()
        }))
    else:
        return make_response(jsonify({'error': 'unauthorized', 'message': '密码错误'}), 403)


@app.route('/api/users', methods=['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        abort(400)    # missing arguments
    if User.query.filter_by(username=username).first() is not None:
        abort(400)    # existing user
    user:User = User(username=username)
    user.hash_password(password.encode())
    db.session.add(user)
    db.session.commit()
    return (jsonify({'username': user.username}), 201,
            {'Location': url_for('get_user', id=user.id, _external=True)})


@app.route('/api/users/<int:id>')
@auth.login_required
def get_user(id):
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'username': user.username,"pwd":user.password_hash})


@app.route('/api/token')
@auth.login_required
def get_auth_token():
    print(g.user.username)
    token = g.user.generate_auth_token(600)
    return jsonify({'token': token.decode('ascii'), 'duration': 600})


@app.route('/api/resource')
@auth.login_required
def get_resource():
    return jsonify({'data': 'Hello, %s!' % g.user.username})


if __name__ == '__main__':
    if not os.path.exists('db.sqlite'):
        db.create_all()
    app.run(debug=True)
