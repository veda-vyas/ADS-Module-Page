from flask import Flask, flash, redirect, render_template, \
     request, jsonify, url_for, session, send_from_directory, \
     make_response, Response as ress, send_file
from flask_sqlalchemy import SQLAlchemy
from cerberus import Validator
from sqlalchemy import cast, func, distinct
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.dialects.postgresql import JSON
from functools import wraps
from datetime import datetime, timedelta
import time
import json
import os
from random import shuffle
import cgi
from werkzeug.utils import secure_filename
from flask import json as fJson
import logging
from logging.handlers import RotatingFileHandler
import uuid
import base64
from flask_mail import Mail, Message
import requests
import hashlib
from flask_csv import send_csv
import pytz
import io
import csv
import inspect
import unittest
import re
import mimetypes
import zipfile
from sqlalchemy.ext.hybrid import hybrid_property
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

if __name__ == "__main__":
        app.debug = True
        app.run(host="0.0.0.0")
