from flask import request, make_response, jsonify
from flask_restful import Resource
from app import db_connect, app
from auth.validation import token_required
from models.users import Connection, User
from passlib.hash import bcrypt_sha256 as sha256
import uuid
import jwt
import datetime
from utilities.responses import response_4xx_5xx


class OneUser(Resource):
    @staticmethod
    @token_required
    def get(current_user, public_id):
        """
        View user
        ---
        tags:
        - "Users"
        security:
        - basicAuth: [admin]
        - apiKey: [admin]
        produces:
        - "application/json"
        parameters:
        - name: x-access-token
          in: header
          description: An authorization header
          required: true
          type: string
        - name: public_id
          in: path
          description: User public id
          required: true
          type: string
        responses:
          200:
            description: "User"
            schema:
              properties:
                public_id:
                  type: string
                name:
                  type: string
                admin:
                  type: boolean
                  default: false
                read_only:
                  type: boolean
                disabled:
                  type: boolean
                  default: false
                connection:
                  type: object
                  default: {}
                info:
                  type: string
          204:
            description: "No content"
          401:
            description: "Invalid token supplied"
          403:
            description: "The user does not have the necessary permissions"
          500:
            description: "Internal error"
        """
        if not current_user.admin:
            return response_4xx_5xx(403)
        print('sql inject:', public_id)
        user = User.query.filter_by(public_id=public_id).first()
        if not user:
            return make_response(jsonify({'message': 'No content'}), 204)
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['admin'] = user.admin
        user_data['read_only'] = user.read_only
        user_data['disabled'] = user.disabled
        user_data['info'] = user.info
        conn = Connection.query.filter_by(public_id=user.public_id).first()
        if not conn:
            user_data['connection'] = {}
        else:
            user_data['connection'] = {'username': conn.username,
                                       'password': conn.password,
                                       'database': conn.database}
        return jsonify({'user': user_data})

    @staticmethod
    @token_required
    def put(current_user, public_id):
        """
        Change user admin setting
        ---
        tags:
        - "Users"
        security:
        - basicAuth: [admin]
        - apiKey: [admin]
        produces:
        - "application/json"
        parameters:
        - name: x-access-token
          in: header
          description: An authorization header
          required: true
          type: string
        - name: public_id
          in: path
          description: User public id
          required: true
          type: string
        responses:
          200:
            description: "User changed to admin"
          204:
            description: "No content"
          401:
            description: "Invalid token supplied"
          403:
            description: "The user does not have the necessary permissions"
          500:
            description: "Internal error"
        """
        if not current_user.admin:
            return response_4xx_5xx(403)
        user = User.query.filter_by(public_id=public_id).first()
        if not user:
            return make_response(jsonify({'message': 'No content'}), 204)
        user.admin = True
        db_connect.session.commit()
        return jsonify({'message': 'User changed to admin'})

    @staticmethod
    @token_required
    def delete(current_user, public_id):
        """
        Delete user
        ---
        tags:
        - "Users"
        security:
        - basicAuth: [admin]
        - apiKey: [admin]
        produces:
        - "application/json"
        parameters:
        - name: x-access-token
          in: header
          description: An authorization header
          required: true
          type: string
        - name: public_id
          in: path
          description: User public id
          required: true
          type: string
        responses:
          200:
            description: "User deleted"
          204:
            description: "No content"
          401:
            description: "Invalid token supplied"
          403:
            description: "The user does not have the necessary permissions"
          500:
            description: "Internal error"
        """
        if not current_user.admin:
            return response_4xx_5xx(403)
        user = User.query.filter_by(public_id=public_id).first()
        if not user:
            return make_response(jsonify({'message': 'No content'}), 204)
        conn = Connection.query.filter_by(public_id=user.public_id).first()
        if conn:
            db_connect.session.delete(conn)
            db_connect.session.commit()
        db_connect.session.delete(user)
        db_connect.session.commit()
        return jsonify({'message': 'The user has been deleted.'})

    @staticmethod
    @token_required
    def patch(current_user, public_id):
        """
        Update user
        ---
        tags:
        - "Users"
        security:
        - basicAuth: [admin]
        - apiKey: [admin]
        produces:
        - "application/json"
        parameters:
        - name: x-access-token
          in: header
          description: An authorization header
          required: true
          type: string
        - in: "body"
          name: "user"
          description: "Updates fields in a user account."
          required: true
          schema:
            type: object
            properties:
              name:
                type: string
              password:
                type: string
              read_only:
                type: boolean
              disabled:
                type: boolean
              info:
                type: string
              db_username:
                type: string
              db_password:
                type: string
              database:
                type: string
        responses:
          200:
            description: "The profile is updated."
          204:
            description: "No content"
          400:
            description: "Bad request"
          401:
            description: "Invalid token supplied"
          403:
            description: "The user does not have the necessary permissions"
          500:
            description: "Internal error"
        """
        if not current_user.admin:
            return response_4xx_5xx(403)
        user = User.query.filter_by(public_id=public_id).first()
        if not user:
            return make_response(jsonify({'message': 'No content'}), 204)
        if request.get_json() is None:
            return response_4xx_5xx(400, 'Did you set content-type?')
        data = request.get_json()
        creds_user = {}
        creds_conn = {}
        update = "UPDATE {} SET {} WHERE public_id = '{}'"
        if 'password' in data:
            creds_user['password'] = sha256.hash(data['password'])
            del data['password']
        if 'name' in data:
            creds_user['name'] = data['name']
            del data['name']
        if 'read_only' in data:
            creds_user['read_only'] = bool(data['read_only'])
            del data['read_only']
        if 'disabled' in data:
            creds_user['disabled'] = bool(data['disabled'])
            del data['disabled']
        if 'info' in data:
            creds_user['info'] = data['info']
            del data['info']
        if 'db_username' in data:
            creds_conn['username'] = data['db_username']
            del data['db_username']
        if 'db_password' in data:
            creds_conn['password'] = data['db_password']
            del data['db_password']
        if 'database' in data:
            creds_conn['database'] = data['database']
            del data['database']
        if len(creds_user) == 0 and len(creds_conn) == 0:
            return make_response(jsonify({'message': 'No content'}), 204)
        if len(data) > 0:
            return response_4xx_5xx(400)
        else:
            if len(creds_user) != 0:
                db_connect.session.query(User).filter(User.public_id == public_id).update(creds_user)
                db_connect.session.commit()
            if len(creds_conn) != 0:
                conn = Connection.query.filter_by(public_id=public_id).first()
                if not conn:
                    new_conn = Connection(public_id=public_id)
                    db_connect.session.add(new_conn)
                    db_connect.session.commit()
                db_connect.session.query(Connection).filter(Connection.public_id == public_id).update(creds_conn)
                db_connect.session.commit()
        return jsonify({'message': 'The profile is updated.'})


class Users(Resource):
    @staticmethod
    @token_required
    def get(current_user):
        """
        View all users
        ---
        tags:
        - "Users"
        security:
        - basicAuth: [admin]
        - apiKey: [admin]
        produces:
        - "application/json"
        parameters:
        - name: x-access-token
          in: header
          description: An authorization header
          required: true
          type: string
        responses:
          200:
            description: "Users"
            schema:
              properties:
                public_id:
                  type: string
                name:
                  type: string
                admin:
                  type: boolean
                  default: false
                read_only:
                  type: boolean
                disabled:
                  type: boolean
                  default: false
                connection:
                  type: object
                  default: {}
                info:
                  type: string
          401:
            description: "Invalid token supplied"
          403:
            description: "The user does not have the necessary permissions"
          500:
            description: "Internal error"
        """
        if not current_user.admin:
            return response_4xx_5xx(403)
        all_users = User.query.all()
        output = []
        for user in all_users:
            user_data = {}
            user_data['public_id'] = user.public_id
            user_data['name'] = user.name
            user_data['admin'] = user.admin
            user_data['read_only'] = user.read_only
            user_data['disabled'] = user.disabled
            user_data['info'] = user.info
            conn = Connection.query.filter_by(public_id=user.public_id).first()
            if not conn:
                user_data['connection'] = {}
            else:
                user_data['connection'] = {'username': conn.username,
                                           'password': conn.password,
                                           'database': conn.database}
            output.append(user_data)
        return jsonify({'users': output})

    @staticmethod
    @token_required
    def post(current_user):
        """
        Create user
        ---
        tags:
        - "Users"
        security:
        - basicAuth: [admin]
        - apiKey: [admin]
        produces:
        - "application/json"
        parameters:
        - name: x-access-token
          in: header
          description: An authorization header
          required: true
          type: string
        - in: "body"
          name: "user"
          description: "Credentials for new user"
          required: true
          schema:
            type: object
            required:
            - name
            - password
            - read_only
            properties:
              name:
                type: string
              password:
                type: string
              read_only:
                type: boolean
              info:
                type: string
              db_username:
                type: string
              db_password:
                type: string
              database:
                type: string
        responses:
          200:
            description: "New user created"
          400:
            description: "Bad request"
          401:
            description: "Invalid token supplied"
          403:
            description: "The user does not have the necessary permissions"
          500:
            description: "Internal error"
        """
        if not current_user.admin:
            return response_4xx_5xx(403)
        if request.get_json() is None:
            return response_4xx_5xx(400, 'Did you set content-type?')
        data = request.get_json()
        hashed_password = sha256.hash(data['password'])
        info = ''
        if 'info' in data:
            info = data['info']
        public_id = str(uuid.uuid4())
        new_user = User(public_id=public_id,
                        name=data['name'],
                        password=hashed_password,
                        admin=False,
                        read_only=bool(data['read_only']),
                        disabled=False,
                        info=info)
        db_connect.session.add(new_user)
        db_connect.session.commit()
        if 'db_username' in data and 'db_password' in data and 'database' in data:
            db_username = data['db_username']
            db_password = data['db_password']
            db_name = data['database']
            new_conn = Connection(public_id=public_id, username=db_username,
                                  password=db_password, database=db_name)
            db_connect.session.add(new_conn)
            db_connect.session.commit()
        return jsonify({'message': 'New user created.'})


class Token(Resource):
    @staticmethod
    @token_required
    def get(current_user):
        """
        Generate new token
        ---
        tags:
        - "Users"
        produces:
        - "application/json"
        parameters:
        - name: x-access-token
          in: header
          description: An authorization header
          required: true
          type: string
        responses:
          200:
            description: "Token"
            schema:
              properties:
                token:
                  type: string
                exp:
                  type: integer
                  description: Seconds to token expire
          401:
            description: "Invalid token supplied"
          403:
            description: "The user does not have the necessary permissions"
          500:
            description: "Internal error"
        """
        if current_user.disabled:
            return response_4xx_5xx(403, 'User disabled')
        inter = datetime.timedelta(minutes=120)
        exp = datetime.datetime.utcnow() + inter
        token = jwt.encode({'public_id': current_user.public_id,
                            'exp': exp},
                           app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8'), 'exp': int(inter.total_seconds())})


class Login(Resource):
    @staticmethod
    def get():
        """
        Login
        ---
        tags:
        - "Users"
        description: ""
        produces:
        - "application/json"
        responses:
          200:
            description: "Token"
            schema:
              properties:
                token:
                  type: string
                exp:
                  type: integer
                  description: Seconds to token expire
          401:
            description: "Invalid username/password supplied"
          403:
            description: "The user does not have the necessary permissions"
          500:
            description: "Internal error"
        """
        auth = request.authorization
        if not auth or not auth.username or not auth.password:
            return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required"'})
        user = User.query.filter_by(name=auth.username).first()
        if not user:
            return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required"'})
        try:
            if sha256.verify(auth.password, user.password):
                if user.disabled:
                    return response_4xx_5xx(403, 'User disabled')
                inter = datetime.timedelta(minutes=120)
                exp = datetime.datetime.utcnow() + inter
                token = jwt.encode({'public_id': user.public_id,
                                    'exp': exp},
                                   app.config['SECRET_KEY'])
                return jsonify({'token': token.decode('UTF-8'), 'exp': int(inter.total_seconds())})
        except:
            pass
        return make_response('Invalid username/password supplied', 401,
                             {'WWW-Authenticate': 'Basic realm="Login required"'})
