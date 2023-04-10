from flask import Flask, jsonify, request, render_template
from flask_basicauth import BasicAuth
from flask_mongoengine import MongoEngine
import os

app = Flask(__name__)
app.config['BASIC_AUTH_USERNAME'] = 'user'
app.config['BASIC_AUTH_PASSWORD'] = 'password'
app.config['MONGODB_SETTINGS'] = {
    'db': 'myapp',
    'host': 'mongo',
    'port': 27017
}

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'my_secret_key')
app.config['SESSION_TYPE'] = 'filesystem'

basic_auth = BasicAuth(app)
db = MongoEngine(app)

class User(db.Document):
    username = db.StringField(required=True)
    password = db.StringField(required=True)

@app.route('/login', methods=['GET', 'POST'])

@app.route('/')
def index():
    return render_template('login.html')

if __name__ == '__main__':
    # Run the app using Gunicorn with SSL/TLS enabled
    options = {
        'bind': '0.0.0.0:443',
        'workers': 4,
        'certfile': './cert.pem',
        'keyfile': './key.pem'
    }
    from gunicorn import gunicorn_app
    gunicorn_app.run(app, **options)
