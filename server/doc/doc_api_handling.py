#!/usr/bin/env python
#
#  HELP
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
from server.doc import getHelpHtml
from server.doc import getDocList
from server.login.login import is_login, current_username
from server.app import DEBUG
TAG = "help"


@app.route('/help', methods=['GET'])
def help():
    return get_help(None)

@app.route('/help/<helpid>', methods=['GET','POST'])
def get_help(helpid):
    log ("Received help request from '%s', method %s" % (request.remote_addr, request.method), TAG, toFile=True)
    login=is_login(request)
    if (helpid is not None) and (len(helpid) > 0):
        html = getHelpHtml(helpid)
        if (html is not None):
            if (DEBUG): logD("help: %s" % html)
            if request.method == 'POST':
                return get_resp(0, html, status_code=common.ERR_HTTP_RESPONSE_OK)
            else:
                from flask import render_template_string
                return render_template_string(html)
        else:
            return get_resp(common.ERR_INVALID_ARGS, "invalid helpid %s" % helpid, status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
    else:
        if request.method == 'POST':
            return get_resp(common.ERR_INVALID_ARGS, "invalid argument", status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
        else:
            doc_list = getDocList()
            return render_template(
                    "help/index.html"
                    , login=login
                    , username=current_username()
                    , doc_list=doc_list
                    )

