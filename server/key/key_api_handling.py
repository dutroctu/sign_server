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
from server.database.account import ACCOUNT_TYPE_ADMIN
from datetime import datetime
from server.login.login import is_login, current_username
from server.database.key_info import KeyInfo
from flask_login import login_required
from server.database.key import KEY_DATA_TYPE_FILE
from server.storage import storageMgr
# import key.key_mng
# import key.import_key
# from server.key.key_mng import keyMgr
# from key import import_key
TAG = "key_api"
# access key home website
@app.route('/key', methods=['GET'])
@login_required
def key_home():
    login=is_login(request)
    login_admin=is_login(request, 
        account_types=[server.database.account.ACCOUNT_TYPE_ADMIN, server.database.account.ACCOUNT_TYPE_MOD, server.database.account.ACCOUNT_TYPE_USER]
    )
    from server.key.key_mng import get_visible_keytool_list
    from server.key.key_mng import get_import_keytool_list
    return render_template("key/key.html", 
        login=login, 
        loginadmin = login_admin, 
        debug=is_debug_db(), 
        username=current_username(),
        key_tool_list=get_visible_keytool_list(),
        import_tool_list=get_import_keytool_list()
        )

def convertKeyInfoJson(o):
    if isinstance(o, KeyInfo): return o.toJson()  
    raise TypeError

# list of key
@app.route('/view_key', methods=['GET','POST'])
@login_required
def view_key_list():
    from server.key.key_mng import keyMgr
    import json
    log ("Received view_key request from '%s', method %s" % (request.remote_addr, request.method), TAG, toFile=True)
    tool = request.args.get('tool', default = None)
    keytool = request.args.get('keytool', default = None)
    if (DEBUG): logD("tool %s" % str(tool), TAG)
    if (DEBUG): logD("keytool %s" % str(keytool), TAG)

    key_list = keyMgr().get_all_keys(tool=tool, keytool=keytool)
    if (DEBUG): logD("key_list %s" % str(key_list), TAG)
    # POST request, mean signing request from client
    if request.method == 'POST':   

        # parse sign requests
        # resp = jsonify({'key_list' : key_list})
        try:
            jdata = json.dumps({"keyList": key_list}, default=convertKeyInfoJson)
            # FIXME
            resp = get_resp(common.ERR_NONE, "OK", jdata, status_code=common.ERR_HTTP_RESPONSE_OK)
        except:
            traceback.print_exc()
            logE("Convert to keyinfo to json", TAG)
            resp = get_resp(common.ERR_EXCEPTION, "Convert keyinfo failed", jdata, status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
        return resp

    #it's GET so return render html to show on browser
    return render_template(
            "key/view_key.html"
            , login=is_login(request)
            , key_list=key_list
            , username=current_username()
            )

# GET: access from browser, POST: send request
@app.route('/import_key/<name>', methods=['GET','POST'])
@login_required
def import_key_request(name):
    from server.key.key_mng import keyMgr
    from server.key.key_mng import get_import_key_tool
    log ("Received import request forfrom '%s', method %s" % (request.remote_addr, request.method), TAG, toFile=True)
    login=is_login(request, 
        account_types=[server.database.account.ACCOUNT_TYPE_ADMIN, server.database.account.ACCOUNT_TYPE_MOD, server.database.account.ACCOUNT_TYPE_USER]
    )
    tool = get_import_key_tool(name)
    help = request.args.get('help', default = None)
    if tool is not None:
        if help is None:
            # POST request, mean request from client or data is submited
            if request.method == 'POST':
                if login:
                    res = common.ERR_FAILED
                    msg = ""
                    log("Start import key %s" % name, TAG, True)
                    [res, msg] = tool.import_key(request)

                    if (res == common.ERR_NONE): #OK
                        resp = get_resp(0, "import key %s success" % 
                                msg.key_info.name, status_code=common.ERR_HTTP_RESPONSE_OK)
                    else:
                        resp = get_resp(res, "import key failed %d (%s). %s" % 
                                (res, common.get_err_msg(res), msg), status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)

                    # TODO: clean temporary data?

                    if (DEBUG): logD("resp %s" % resp, TAG)
                    return resp
                else:        
                    return get_resp(
                        error=common.ERR_PROHIBIT, 
                        message="Not login with proper account", 
                        status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
            #it's GET so return render html to show on browser
            return tool.get_html_render(request)
        else:
            log("Request help for %s" % help, TAG, True)
            html = tool.get_help(request, help)
            if html is not None:
                if request.method == 'POST':
                    return get_resp(0, html, status_code=common.ERR_HTTP_RESPONSE_OK)
                else:
                    from flask import render_template_string
                    return render_template_string(html)
            else:
                return get_resp(
                    error=common.ERR_INVALID_ARGS, 
                    message="No information for %s" % help, 
                    status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
    else:
        return get_resp(
            error=common.ERR_NOT_SUPPORT, 
            message="tool '%s' not support" % name, 
            status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)


# GET: access from browser, POST: send request
@app.route('/genkey/<keytool>', methods=['GET','POST'])
@login_required
def get_key(keytool):
    from server.key.key_mng import keyMgr
    from server.key.key_mng import get_keytool_from_name
    log ("Received genkey request for from '%s', method %s" % (request.remote_addr, request.method), TAG, toFile=True)
    login=is_login(request, 
        account_types=[server.database.account.ACCOUNT_TYPE_ADMIN, server.database.account.ACCOUNT_TYPE_MOD, server.database.account.ACCOUNT_TYPE_USER]
    )
    tool = get_keytool_from_name(keytool)
    help = request.args.get('help', default = None)
    if tool is not None:
        if help is None:
            # POST request, mean request from client or data is submited
            if request.method == 'POST':
                if login:
                    res = common.ERR_FAILED
                    msg = ""
                    log("Start generate key %s" % keytool, TAG, True)
                    [res, msg] = tool.generate_key(request)

                    if (res == common.ERR_NONE): #OK
                        resp = get_resp(0, "generate key success"  
                                , status_code=common.ERR_HTTP_RESPONSE_OK)
                    else:
                        resp = get_resp(res, "generate key failed %d (%s). %s" % 
                                (res, common.get_err_msg(res), msg), status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)

                    # TODO: clean temporary data?

                    if (DEBUG): logD("resp %s" % resp, TAG)
                    return resp
                else:        
                    return get_resp(
                        error=common.ERR_PROHIBIT, 
                        message="Not login with proper account", 
                        status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)

            #it's GET so return render html to show on browser
            return tool.get_html_render(request)
        else:
            html = tool.get_help(request, help)
            if html is not None:
                if request.method == 'POST':
                    return get_resp(0, html, status_code=common.ERR_HTTP_RESPONSE_OK)
                else:
                    from flask import render_template_string
                    return render_template_string(html)
            else:
                get_resp(
                    error=common.ERR_INVALID_ARG, 
                    message="Invalid help id" % help, 
                    status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
    else:
        return get_resp(
            error=common.ERR_NOT_SUPPORT, 
            message="tool '%s' not support" % keytool, 
            status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)


# download of key
@app.route('/key/download/<key_id>', methods=['GET', 'POST'])
@login_required
def download_public_key(key_id):
    from server.key.key_mng import keyMgr
    log ("Received download_key request from '%s', method %s" % (request.remote_addr, request.method), TAG, toFile=True)
    login=is_login(request)
    if login: # require login first
        # get current login user
        if key_id is not None:
            log("get download key package %s" % (key_id), TAG)

            [ret, msg] = keyMgr().getPublicDownloadKeys(key_id)

            if (DEBUG): logD("download key result %d" % ret, TAG)
            if ret == common.ERR_NONE:
                # msg is path to file if success
                fname = os.path.basename(msg)
                if (DEBUG): logD("download key: %s" % msg, TAG)
                resp = send_file(msg, key_id, as_attachment=True, attachment_filename=fname, cache_timeout=0) 
                # TODO: FIXME : auto delete download file....
            else: # get downlaod key failed
                resp = get_resp(
                    error=ret, 
                    message=msg, 
                    status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
        else: # invalid keyid/user id
            resp = get_resp(
                    error=common.ERR_INVALID_ARGS, 
                    message="Not keyid", 
                    status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
        return resp
    else:        
        return get_resp(
            error=common.ERR_PROHIBIT, 
            message="Not login with proper account", 
            status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)

@app.route('/keyinfo/<keyid>', methods=['GET'])
@login_required
def view_keyinfo(keyid):
    from server.key.key_mng import keyMgr
    from server.key.key_mng import POLICY_ACTION_LIST
    from server.database.key import KEY_STATUS_CNAME
    from server.key.key_mng import get_keytool_from_name
    log ("Received view_keyinfo request from '%s', method %s" % (request.remote_addr, request.method), TAG, toFile=True)
    login=is_login(request
    )
    if login:
        if keyid is not None:
            if (DEBUG): logD("get_key %s" % keyid, TAG)
            keyinfo = keyMgr().get_key(keyid)
            if keyinfo is not None:
                status = KEY_STATUS_CNAME[keyinfo.status] if keyinfo.status in KEY_STATUS_CNAME else "Unknown"
                target_keytools = keyinfo.getKeyTools()
                key_info_status = ""
                if (target_keytools is not None and len(target_keytools) > 0):
                    for keytool in target_keytools:
                        tool = get_keytool_from_name(keytool)
                        if (tool != None):
                            key_info_status += "* Check key for tool %s:\n" % keytool
                            [ret, keystatus] = tool.check_key(keyid, is_login(request, ACCOUNT_TYPE_ADMIN))
                            key_info_status += "Check result %d;\n" % ret
                            key_info_status += "keystatus %s;\n" % keystatus
                        else:
                            key_info_status += "* Not found tool for name %s:\n" % keytool
                else:
                    key_info_status += "not found any keytool"
                return render_template("key/view_key_info.html", 
                    # common
                    login=login, 
                    debug=is_debug_db(), 
                    username=current_username(),
                    key=keyinfo,
                    action_list=POLICY_ACTION_LIST,
                    status=status,
                    key_info_status=key_info_status
                    )
            else:
                logE("Key %s not found" % keyid, TAG)
                return get_resp(
                            error=common.ERR_NOT_FOUND, 
                            message="key not found", 
                            status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
        else:
            return get_resp(
                        error=common.ERR_INVALID_ARGS, 
                        message="Invalid key", 
                        status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
    else:
        # not login yet
        return get_resp(
            error=common.ERR_PROHIBIT, 
            message="Not login with proper account", 
            status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)