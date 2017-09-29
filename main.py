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


@app.route('/')
def index():
    try:
        return render_template('index.html')
    except Exception as e:
        return render_template('error.html')

@app.route('/module/<number>')
def module(number=None):
    if number==None:
        return render_template('module1.html')
    else:
        try:
            return render_template('module'+number+'.html')
        except Exception as e:
            return render_template('error.html')

root = os.path.join(os.path.dirname(os.path.abspath(__file__)))
@app.route('/styles/<path:path>')
def send_stylesheets(path):
    app.logger.info("seeking for %s from %s at %s"%(path, request.headers.get('X-Forwarded-For', request.remote_addr), datetime.now()))
    return send_from_directory(root+"/styles", path)

@app.route('/scripts/<path:path>')
def send_javascripts(path):
    app.logger.info("seeking for %s from %s at %s"%(path, request.headers.get('X-Forwarded-For', request.remote_addr), datetime.now()))
    return send_from_directory(root+"/scripts", path)

if __name__ == "__main__":
        app.debug = True
        app.run(host="0.0.0.0")
