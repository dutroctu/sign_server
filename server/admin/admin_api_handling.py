#!/usr/bin/env python
#
#  KEY MANAGEMENT
#


from flask import Flask
from flask_restful import Api, Resource, reqparse
from flask import send_file
from flask import render_template
from flask import request, abort, jsonify, send_from_directory
from server.app import app
from server.app import getModelList
from server.app import getProjectList
from server.app import KEEP_OUTPUT_FILE
from server.app import DEBUG
from server.app import is_debug_db
import os
from server.applog import log
from server.applog import logE
from server.applog import logD
from server.app import get_resp
from server import common as common
import traceback
import shutil
import server.database.account
from server.database.key import Key
from server.database.key import KeyFile
from server.database.key import KEY_STATUS_NOT_READY
from server.database.key import KEY_STATUS_READY
from server.database.key import KEY_STATUS_DELETED
from server.database.key import ALG_LIST
from datetime import datetime
from server.login.login import is_login, current_username
from flask_login import login_required
from server.database.key import KEY_DATA_TYPE_FILE
# from server.login.user_mng import usrMgr

from server import database as database

import server.admin.admin_user_api_handling
import server.admin.admin_key_api_handling
import server.admin.admin_backup_api_handling
import server.admin.admin_log_api_handling
import server.admin.admin_monitor_storage

# from login import user_mng
# from server.login.add_user import AddUserRequest
TAG = "admin"

#
# home page of admin
# ADMIN account only
#
@app.route('/admin', methods=['GET'])
@login_required
def admin_home():
    # only admin can open this side
    login=is_login(request, database.account.ACCOUNT_TYPE_ADMIN)
    return render_template("admin/admin.html", login=login, debug=is_debug_db(), username=current_username())

