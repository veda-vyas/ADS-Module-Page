from flask import Flask, flash, redirect, render_template, \
     request, jsonify, url_for, session, send_from_directory, \
     make_response, Response as ress, send_file
from datetime import datetime, timedelta
import time
import json
import os
import logging
from logging.handlers import RotatingFileHandler
import sys
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import LoginManager, login_required, login_user, \
    logout_user, current_user, UserMixin
from requests_oauthlib import OAuth2Session
from requests.exceptions import HTTPError
from config import BaseConfig
import StringIO
import csv

root = os.path.join(os.path.dirname(os.path.abspath(__file__)))

class Auth:
    CLIENT_ID = ('891614416155-5t5babc77fivqfslma1c3u6r2r9fp1o1.apps.googleusercontent.com')
    CLIENT_SECRET = 'UnGr0t5VT0d3l4PLgICkQoy6'
    REDIRECT_URI = 'https://localhost:5000/oauth2callback'
    AUTH_URI = 'https://accounts.google.com/o/oauth2/auth'
    TOKEN_URI = 'https://accounts.google.com/o/oauth2/token'
    USER_INFO = 'https://www.googleapis.com/userinfo/v2/me'
    SCOPE = ['profile', 'email']

class Config:
    APP_NAME = "MSIT Course Page"
    SECRET_KEY = "somethingsecret"

# class DevConfig(Config):
#     DEBUG = True
#     SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:veda1997@localhost/module_page'

# config = {
#     "dev": DevConfig,
#     "default": DevConfig
# }

app = Flask(__name__)

app.debug_log_format = "[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s"
log_path = os.path.join(os.getcwd(),'logs.log')
log_path = 'logs.log'
logHandler = RotatingFileHandler(log_path, maxBytes=10000, backupCount=1)
logHandler.setLevel(logging.NOTSET)
app.logger.addHandler(logHandler)
app.logger.setLevel(logging.NOTSET)
login_log = app.logger
app.debug = True
app.secret_key = "some_secret"
app.config.from_object(BaseConfig)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.session_protection = "strong"

from werkzeug.serving import make_ssl_devcert
make_ssl_devcert('./ssl', host='localhost')

class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=True)
    avatar = db.Column(db.String(200))
    tokens = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow())

class Activity(db.Model):
    __tablename__ = "activity"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False)
    name = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow())

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def get_google_auth(state=None, token=None):
    if token:
        return OAuth2Session(Auth.CLIENT_ID, token=token)
    if state:
        return OAuth2Session(
            Auth.CLIENT_ID,
            state=state,
            redirect_uri=Auth.REDIRECT_URI)
    oauth = OAuth2Session(
        Auth.CLIENT_ID,
        redirect_uri=Auth.REDIRECT_URI,
        scope=Auth.SCOPE)
    return oauth

@app.route('/')
@login_required
def index():
    try:
        activity = Activity()
        activity.email = session['email']
        activity.name = "HOMEPAGE"
        activity.timestamp = datetime.utcnow()
        db.session.add(activity)

        db.session.commit()
        return render_template('index.html')
    except Exception as e:
        app.logger.info(e)
        return render_template('error.html')

@app.route('/login')
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    google = get_google_auth()
    auth_url, state = google.authorization_url(
        Auth.AUTH_URI, access_type='offline')
    session['oauth_state'] = state
    return redirect(auth_url)

@app.route('/oauth2callback')
def callback():
    if current_user is not None and current_user.is_authenticated:
        return redirect(url_for('index'))
    if 'error' in request.args:
        if request.args.get('error') == 'access_denied':
            return 'You denied access.'
        return 'Error encountered.'
    if 'code' not in request.args and 'state' not in request.args:
        return redirect(url_for('login'))
    else:
        google = get_google_auth(state=session['oauth_state'])
        try:
            token = google.fetch_token(
                Auth.TOKEN_URI,
                client_secret=Auth.CLIENT_SECRET,
                authorization_response=request.url)
        except HTTPError:
            return 'HTTPError occurred.'
        google = get_google_auth(token=token)
        resp = google.get(Auth.USER_INFO)
        if resp.status_code == 200:
            user_data = resp.json()
            email = user_data['email']
            user = User.query.filter_by(email=email).first()
            if user is None:
                user = User()
                user.email = email
            user.name = user_data['name']
            print(token)
            user.tokens = json.dumps(token)
            user.avatar = user_data['picture']
            db.session.add(user)

            activity = Activity()
            activity.email = email
            activity.name = "LOGIN"
            activity.timestamp = datetime.utcnow()
            db.session.add(activity)

            db.session.commit()
            login_user(user)
            session['email'] = email
            app.logger.info(session['email'])
            return redirect(url_for('index'))
    return 'Could not fetch your information.'

@app.route('/logout')
@login_required
def logout():
    activity = Activity()
    activity.email = session['email']
    activity.name = "LOGOUT"
    activity.timestamp = datetime.utcnow()
    db.session.add(activity)

    db.session.commit()
    logout_user()
    return redirect(url_for('login'))

@app.route('/module/<number>')
@login_required
def module(number=None):
    activity = Activity()
    activity.email = session['email']
    activity.name = "MODULE"+str(number)
    activity.timestamp = datetime.utcnow()
    db.session.add(activity)

    db.session.commit()
    if number==None:
        return render_template('module1.html')
    else:
        try:
            return render_template('module'+number+'.html')
        except Exception as e:
            return render_template('error.html')

@app.route('/saveactivity', methods=["POST"])
@login_required
def saveactivity():
    try:
        data = json.loads(request.get_data())
        activity = Activity()
        activity.email = session['email']
        activity.name = data['name']
        activity.timestamp = datetime.utcnow()
        db.session.add(activity)

        db.session.commit()
        return "success"
    except Exception as e:
        app.logger.info(e)
        return "failure"

@app.route('/activity/<module_number>/<number>')
@login_required
def activity(module_number=None,number=None):
    activity = Activity()
    activity.email = session['email']
    activity.name = "MODULE"+str(module_number)+" ACTIVITY"+str(number)
    activity.timestamp = datetime.utcnow()
    db.session.add(activity)

    db.session.commit()
    if module_number==None and number==None:
        return render_template('error.html')
    else:
        try:
            return render_template('module'+module_number+'/activity'+number+'.html')
        except Exception as e:
            return render_template('error.html')

@app.route('/styles/<path:path>')
@login_required
def send_stylesheets(path):
    app.logger.info("seeking for %s from %s at %s"%(path, request.headers.get('X-Forwarded-For', request.remote_addr), datetime.now()))
    return send_from_directory(root+"/styles", path)

@app.route('/scripts/<path:path>')
@login_required
def send_javascripts(path):
    app.logger.info("seeking for %s from %s at %s"%(path, request.headers.get('X-Forwarded-For', request.remote_addr), datetime.now()))
    return send_from_directory(root+"/scripts", path)

def get_students_activity():
        result = Activity.query.all()
        table = []
        student_temp = {"name":None, "rollno":None, "Speaking":0, "Writing":0, "Listening":0, "Reading":0}
        for entry in result:
            activity = {}
            activity["email"] = entry.email
            activity["timestamp"] = entry.timestamp
            activity["activity"] = entry.name
            table.append(activity)

        return table

def render_csv_from_student_activity(data):
        csvList = []
        header = [
                    "User",
                    "Timestamp",
                    "Activity"
                ]
        csvList.append(header)
        for csv_line in data:
            row = [csv_line["email"],
                    csv_line["timestamp"],
                    csv_line["activity"]
                ]
            csvList.append(row)
        si = StringIO.StringIO()
        cw = csv.writer(si)
        app.logger.info(csvList)        
        cw.writerows(csvList)
        output = make_response(si.getvalue())
        output.headers["Content-Disposition"] = "attachment; filename=StudentActivity.csv"
        output.headers["Content-type"] = "text/csv"
        return output

@app.route('/downloadStudentActivity')
@login_required
def downloadStudentActivity():
    if request.method == 'GET':
        data = get_students_activity()
    return render_csv_from_student_activity(data)

if __name__ == "__main__":
        app.debug = True
        db.create_all()
        app.run(ssl_context=('./ssl.crt', './ssl.key'))
