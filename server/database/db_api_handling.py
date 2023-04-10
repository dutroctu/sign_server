#!/usr/bin/env python
#
#  DB control
#

# http://docs.mongoengine.org/apireference.html#fields
# https://flask-pymongo.readthedocs.io/en/latest/
# https://pythonbasics.org/flask-mongodb/
# http://docs.mongoengine.org/projects/flask-mongoengine/en/latest/

from flask import Flask
from flask_restful import Api, Resource, reqparse
from flask import send_file
from flask import render_template
from flask import request, abort, jsonify, send_from_directory
from server.app import app
from server.app import is_debug_db
import os
from server.applog import log
from server.applog import logE
from server.applog import logD
from flask_login import login_required
from server import common as common

from server.app import get_resp

