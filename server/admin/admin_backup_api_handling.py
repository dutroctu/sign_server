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


# from login import user_mng
# from server.login.add_user import AddUserRequest
TAG = "adminbackup"


@app.route("/backup", methods=['GET','POST'])
@login_required
def backup():
    from server.backup.backup_mgr import backupMgr
    log ("Received backup request from '%s', method %s" % (request.remote_addr, request.method), TAG, toFile=True)
    login=is_login(request, database.account.ACCOUNT_TYPE_ADMIN)
    if request.method == 'POST':
        password = common.extract_form_request(request, common.PARAM_PASSWORD).strip()
        if login:
            ret = backupMgr().backup(password)
            if (ret == common.ERR_NONE):
                return get_resp(
                    error=0, 
                    message="Backup successful",
                    status_code=common.ERR_HTTP_RESPONSE_OK)
            else:
                return get_resp(
                    error=ret, 
                    message="Failed to backup, ret %d (%s)" % (ret, common.get_err_msg(ret)), 
                    status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
        else:
            return get_resp(common.ERR_PROHIBIT, "Not login as admin yet", status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
        #it's GET so return render html to show on browser
    return render_template(
            "admin/backup.html"
            , login=login
            , username=current_username()
            , account_type=database.account.ACCOUNT_TYPE_ID_CNAME
            )
