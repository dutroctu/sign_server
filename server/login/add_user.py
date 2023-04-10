#!/usr/bin/env python
#
#  IMPORT KEY
#


from flask import Flask
from flask_restful import Api, Resource, reqparse
from flask import send_file
from flask import render_template
from flask import request, abort, jsonify, send_from_directory
from server.app import app
import os
from server.applog import log
from server.applog import logE
from server.applog import logD
from server.app import get_resp
from server.app import getRootInputDir
import server.login
import traceback
from server import common as common
from server.database.user_info import UserInfo
from flask_login import login_required
from server.common import extract_form_request
from server.login.user_mng import usrMgr
from server import database as database
from server.app import DEBUG

TAG = "AddUser"
class AddUserRequest(object):
    access_token = "" # for log in feature
    user_info = None
    def parse(self, __request):
        # Parse request, build key info
        # TODO validate UserInfo info
        if (DEBUG): logD("parse add user request", TAG)
        if (DEBUG): logD(__request.form, TAG)
        self.user_info = UserInfo()
        self.user_info.username = extract_form_request(request, common.PARAM_NAME).strip()
        self.user_info.fullname = extract_form_request(request, "fullname").strip()
        self.user_info.email = extract_form_request(request, "email").strip()
        self.user_info.phone = extract_form_request(request, "phone").strip()
        self.user_info.note = extract_form_request(request, "note").strip()
        self.user_info.type = extract_form_request(request, "type", True, default_data=database.account.ACCOUNT_TYPE_UNKNOWN)

        
        return [common.ERR_NONE, "OK"]

    def toString(self, isFull=False):
        str = ""

        str += "\n"
        return str
