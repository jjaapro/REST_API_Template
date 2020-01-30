from flask import request
import jwt
from functools import wraps
from utilities.responses import response_4xx_5xx
from app import app
from models.users import User


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return response_4xx_5xx(401)
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return response_4xx_5xx(401)
        return f(current_user, *args, **kwargs)
    return decorated
