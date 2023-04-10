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
from server.resource.res import getResPath
from server.resource.res import getResList
from server.login.login import is_login, current_username
from server.app import DEBUG
TAG = "help"


# @app.route('/help', methods=['GET'])
# def help():
#     return get_help(None)

# @app.route('/res/<resid>', methods=['GET','POST'])
# def get_help(helpid):
#     log ("Received help request from '%s', method %s" % (request.remote_addr, request.method), TAG, toFile=True)
#     login=is_login(request)
#     if (helpid is not None) and (len(helpid) > 0):
#         html = getHelpHtml(helpid)
#         if (html is not None):
#             if (DEBUG): logD("help: %s" % html)
#             if request.method == 'POST':
#                 return get_resp(0, html, status_code=common.ERR_HTTP_RESPONSE_OK)
#             else:
#                 from flask import render_template_string
#                 return render_template_string(html)
#         else:
#             return get_resp(common.ERR_INVALID_ARGS, "invalid helpid %s" % helpid, status_code=common.ERR_HTTP_RESPONSE_OK)
#     else:
#         if request.method == 'POST':
#             return get_resp(common.ERR_INVALID_ARGS, "invalid argument", status_code=common.ERR_HTTP_RESPONSE_OK)
#         else:
#             doc_list = getDocList()
#             return render_template(
#                     "help/index.html"
#                     , login=login
#                     , username=current_username()
#                     , doc_list=doc_list
#                     )



# #get example
# @app.route("/res")
# def list_res_files():
#     """Endpoint to list files on the server."""

#     __link = ""
#     from server.app import getDocDir
#     res_dir = 
#     for filename in os.listdir(EXAMPLE_DIRECTORY):
#         path = os.path.join(EXAMPLE_DIRECTORY, filename)
#         if os.path.isfile(path):
#             __link += "<a href=\"/example/%s\">%s</a><br/>" %(filename, filename) + "\n"

#     return '''
# <body class="body">
#    <div class="container" align="left">
# 		%s
#    </div>
# </body>
#     ''' % __link

# #download example
# @app.route("/res/<filename>")
# def get_example_file(filename):
#     """Download example file."""
#     # FIXME: I tried url_value_preprocessor and catch all routes to make common processing, but not success
#     # if you find better way, please update this :)
#     import server.monitor.system_report
#     checkResp = server.monitor.system_report.check_system(request)
#     if checkResp is not None:
#         return checkResp

#     return 

@app.route('/res', methods=['GET'])
def get_res_list():
    return get_res(None)

@app.route('/res/<resid>', methods=['GET','POST'])
def get_res(resid):
    log ("Received res request from '%s', method %s" % (request.remote_addr, request.method), TAG, toFile=True)
    # FIXME: I tried url_value_preprocessor and catch all routes to make common processing, but not success
    # if you find better way, please update this :)
    import server.monitor.system_report
    checkResp = server.monitor.system_report.check_system(request)
    if checkResp is not None:
        return checkResp
    login=is_login(request)
    if (resid is not None) and (len(resid) > 0):
        path = getResPath(resid)
        if (path is not None) and os.path.exists(path):
            return send_file(path, as_attachment=True)
        else:
            return get_resp(common.ERR_INVALID_ARGS, "invalid resid %s" % resid, status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
    else:
        doc_list = getResList()
        return render_template(
                "resource.html"
                , login=login
                , username=current_username()
                , doc_list=doc_list
                )

