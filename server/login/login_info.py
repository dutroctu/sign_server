#!/usr/bin/env python
#
#  KOGIN INFO
#


from flask import Flask
from flask_restful import Api, Resource, reqparse
from flask import send_file
from flask import render_template
from flask import request, abort, jsonify, send_from_directory
# from server.app import app
import os
from server import applog as applog 
from server import common as common
import traceback
import server.database.account
from server.database.db_mgr import db
from server import database as database

# Login Info
class LoginInfo:
    # access_token is session id
    sessionid = None
    userid = None
    username = None
    fullname = None
    remoteIP = None
    remotePort = None
    login_time = None
    last_active_time = None
    is_authenticated = False # require for flash_login
    is_anonymous = False # require for flash_login
    is_active = False # require for flash_login
    type = database.account.ACCOUNT_TYPE_UNKNOWN

    def __init__(self):
        self.userid = None
        self.sessionid = None
        self.username = None
        self.fullname = None
        self.remoteIP = None
        self.remotePort = None
        self.login_time = None
        self.last_active_time = None
        self.is_authenticated = False # require for flash_login
        self.is_anonymous = False # require for flash_login
        self.is_active = False # require for flash_login
        self.type = database.account.ACCOUNT_TYPE_UNKNOWN

    def get_id(self): # require for flash_login
        return self.sessionid
    