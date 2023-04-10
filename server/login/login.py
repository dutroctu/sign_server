#!/usr/bin/env python
#
#  MANAGE LOGIN 
#

# https://flask-login.readthedocs.io/en/latest/
# https://hackersandslackers.com/flask-login-user-authentication/
# https://www.digitalocean.com/community/tutorials/how-to-add-authentication-to-your-app-with-flask-login
# https://github.com/PrettyPrinted/flask_auth_scotch/blob/master/project/
# https://realpython.com/using-flask-login-for-user-management-with-flask/


from flask import Flask, Blueprint, flash, redirect, url_for
from flask_restful import Api, Resource, reqparse
from flask import send_file
from flask import render_template
from flask import request, abort, jsonify, send_from_directory
# from server.app import app
import os
from server import common as common
from server.applog import log
from server.applog import logD
from server.applog import logE
# from server.app import get_resp
# from server.login.user_mng import UserMgr
# from server.login.session import SessionMng
# from server.login.login_info import LoginInfo
# import server.login.login_info
# from server.login.login_mng import LoginMgr
# from server.common import PARAM_ACCESS_TOKEN
from flask_login import LoginManager 
from flask_login import login_user, current_user
import json
from server import database as database
import traceback

# flask login manager
login_manager = LoginManager()
auth = Blueprint('auth', __name__)

TAG = "login"

# init login management
def init_login_management(app):
    log("init_login_management", toFile=False)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = u"Request require login."
    login_manager.login_message_category = "info"
    # app.config['USE_SESSION_FOR_NEXT'] = True
    login_manager.init_app(app)

    return common.ERR_NONE

# check if access token is valid
def is_login_access_token(access_token):
    if access_token is not None:
        from server.login.login_mng import LoginMgr
        login_info = LoginMgr.get_login_info(access_token)
        if (login_info is not None):
            return True
    return False

# check if client already signed in or not
def is_login(request = None, account_type=0, account_types=None):
    # FIXME: I tried url_value_preprocessor and catch all routes to make common processing, but not success
    # if you find better way, please update this :)
    import server.monitor.system_report
    if not server.monitor.system_report.sysReport().isReady:
        return False

    import server.database.account
    if account_type == database.account.ACCOUNT_TYPE_UNKNOWN:
        if account_types is None or len(account_types) == 0:
            return current_user.is_authenticated
        for type in account_types:
            if current_user.is_authenticated and current_user.type == type:
                return True
        return False
    else:
        return current_user.is_authenticated and current_user.type == account_type

# check if client already signed in or not
def current_username():
    if is_login():
        return current_user.username
    else:
        return "Guest"

def current_userid():
    if is_login():
        try:
            return current_user.userid
        except:
            traceback.print_exc()
            logE("Exception when get userid", TAG)
            return None
    else:
        return None