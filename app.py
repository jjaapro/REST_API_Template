from flask import Flask
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from flasgger import Swagger
from gevent.pywsgi import WSGIServer


DB_PATH = 'credentials.db'
STATIC_DIR = '/static'


app = Flask(__name__)

app.config['SWAGGER'] = {'title': 'AmoWeb'}
app.config['SECRET_KEY'] = 'y68JOkLcgM92nAqRGCzJn6N195z83OEc'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + DB_PATH

api = Api(app)

template = {
  "info": {
    "title": "",
    "contact": {
      "responsibleOrganization": "",
      "email": ""
    },
    "version": ""
  },
  "host": "127.0.0.1:8080",
  "basePath": "/",
  "schemes": [
  ]
}
swagger_config = {
        "headers": [
        ],
        "specs": [
            {
                "endpoint": 'apispec',
                "route": '/apispec.json',
                "rule_filter": lambda rule: True,  # all in
                "model_filter": lambda tag: True,  # all in
            }
        ],
        "static_url_path": STATIC_DIR,
        "swagger_ui": True,
        "hide_top_bar": True,
        "specs_route": "/",
    }

db_connect = SQLAlchemy(app)
swagger = Swagger(app, template=template, config=swagger_config)


from controllers import users


def add_resources():
    api.add_resource(users.Users, '/user')
    api.add_resource(users.OneUser, '/user/<public_id>')
    api.add_resource(users.Token, '/token')
    api.add_resource(users.Login, '/login')


def cli(production):
    add_resources()
    if production:
        srv = WSGIServer(('0.0.0.0', 8080), app, log=app.logger)
        srv.serve_forever()
    else:
        app.run(host='127.0.0.1', port=8080, debug=False)


if __name__ == '__main__':
    cli(None)
