from flask import jsonify, make_response


def response_4xx_5xx(code, info=''):
    """
    responses:
        400:
        description: "Bad request"
        401:
        description: "Invalid token supplied"
        403:
        description: "The user does not have the necessary permissions"
        404:
        description: "Invalid"
        500:
        description: "Internal error"
    """
    message = ''
    if code == 400:
        message = 'Bad request'
    if code == 401:
        message = 'Invalid token supplied'
    if code == 403:
        message = 'The user does not have the necessary permissions'
    if code == 404:
        message = 'Invalid'
    if code == 500:
        message = 'Internal error'
    return make_response(jsonify({'message': message, 'code': code, 'info': info}), code)
