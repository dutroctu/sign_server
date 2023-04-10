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
from server.login.login import is_login, current_username, current_userid
from flask_login import login_required
from server.database.key import KEY_DATA_TYPE_FILE
# from server.login.user_mng import usrMgr

from server import database as database
from server.storage.storage_mgr import storageMgr

# from login import user_mng
# from server.login.add_user import AddUserRequest
TAG = "adminkey"

# list of key
@app.route('/manage_key', methods=['GET','POST'])
@login_required
def manage_key():
    from server.key.key_mng import keyMgr
    log ("Received manage_key request from '%s', method %s" % (request.remote_addr, request.method), TAG, toFile=True)
    login=is_login(request, 
        account_types=[server.database.account.ACCOUNT_TYPE_ADMIN]
    )

    key_list = keyMgr().get_all_keys()
    # POST request, mean signing request from client
    if request.method == 'POST':   

        # parse sign requests
        # resp = jsonify({'key_list' : key_list}) 
        # FIXME
        resp = get_resp(200, "OK", {"keyList": key_list})
        return resp

    #it's GET so return render html to show on browser
    return render_template(
            "admin/manage_key.html"
            , login=login
            , key_list=key_list
            , username=current_username()
            )


# download of key
@app.route('/download_key/<key_id>', methods=['GET', 'POST'])
@login_required
def download_key(key_id):
    from server.key.key_mng import keyMgr
    log ("Received download_key request from '%s', method %s" % (request.remote_addr, request.method), TAG, toFile=True)
    login=is_login(request)
    if login: # require login first
        userid = current_userid()
        # get current login user
        if userid is not None and key_id is not None:
            # ret id-rsa from request form if any, it'll be used to check match with one in policy
            rsa = common.extract_form_request(request, "rsa", default_data=None)
            
            # remove space
            rsa = rsa.strip() if rsa is not None else None

            log("get download key package %s for user %s" % (key_id, userid), TAG)

            [ret, msg] = keyMgr().getDownloadKeys(key_id, userid, request.remote_addr, rsa)

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
                    message="Not keyid or userid", 
                    status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
        return resp
    else:        
        return get_resp(
            error=common.ERR_PROHIBIT, 
            message="Not login with proper account", 
            status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)

#
# delete key
#
@app.route("/delete_key", methods=["POST"])
@login_required
def delete_key():
    from server.key.key_mng import keyMgr
    log ("Received delete request from '%s', method %s" % (request.remote_addr, request.method), TAG, toFile=True)

    # only allow admin user
    login=is_login(request, 
        account_types=[server.database.account.ACCOUNT_TYPE_ADMIN]
    )

    if login:
        jsondata = request.json
        key_id = jsondata['key_id'] if 'key_id' in jsondata else None

        if key_id is not None:
            # call to delete key
            [ret, key_info] = keyMgr().delete_key(key_id)
        
            if (ret == common.ERR_NONE):
                return get_resp(
                    error=0, 
                    message="Delete key %s (%s) successful" % (key_id, key_info.name), 
                    status_code=common.ERR_HTTP_RESPONSE_OK)
            else:
                return get_resp(
                    error=ret, 
                    message="Failed to delete key %s, ret %d (%s)" % (key_id, ret, common.get_err_msg(ret)), 
                    status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
        else: # invalid key id
            return get_resp(
                    error=common.ERR_INVALID_ARGS, 
                    message="No key id", 
                    status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
    else:        
        return get_resp(
            error=common.ERR_PROHIBIT, 
            message="Not login with proper account", 
            status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)

#
# Set default key request
#
@app.route("/setdefaultkey", methods=["POST"])
@login_required
def setdefaultkey():
    from server.key.key_mng import keyMgr
    log ("Received setdefaultkey request from '%s', method %s" % (request.remote_addr, request.method), TAG, toFile=True)
    login=is_login(request, 
        account_types=[server.database.account.ACCOUNT_TYPE_ADMIN]
    )
    if login:
        jsondata = request.json
        key_id = jsondata['key_id'] if 'key_id' in jsondata else None
        default = jsondata['default'] if 'default' in jsondata else None

        if key_id is not None and default is not None:
            key_info = keyMgr().get_key(key_id)
            if key_info is not None:
                if key_info.isdefault == default:
                    return get_resp(
                    error=common.ERR_FAILED, 
                    message="Key %s, default already set to %d" % (key_info.name, default), 
                    status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
                else:
                    # check if default already set for other key
                    # which match with project/model/target tool/key tool
                    key_info2 = keyMgr().get_default_key2(
                        projects=key_info.getProjects(), 
                        models=key_info.getModels(), 
                        tools=key_info.getTools(),
                        keytools=key_info.getKeyTools()
                        )
                    if key_info2 is not None and key_info2.id != key_id and default:
                        message="Found other key (%s) set as default key for same project/model/sign tool/keytool. Please unset it first" % (key_info2.name)
                        logE(message, TAG)
                        return get_resp(
                        error=common.ERR_EXISTED, 
                        message=message, 
                        status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
                    else: # set default
                        if (DEBUG): logD("call to set default", TAG)
                        ret = keyMgr().set_default(key_id, default)

            else: # key not found
                return get_resp(
                error=common.ERR_NOT_FOUND, 
                message="Not found key %s" % (key_info.name), 
                status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
        else: # invalid argument
            ret = common.ERR_INVALID_ARGS
            logE("failed to set default, invalid keyid or default value", TAG)
        
        if (ret == common.ERR_NONE):
            return get_resp(
                error=0, 
                message="Change default state of key %s (%s) successful" % (key_id, key_info.name), 
                status_code=common.ERR_HTTP_RESPONSE_OK)
        else:
            return get_resp(
                error=ret, 
                message="Failed to change default state of key, ret %d (%s)" % (ret, common.get_err_msg(ret)), 
                status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
    else: # not login yet
        return get_resp(
            error=common.ERR_PROHIBIT, 
            message="Not login with proper account", 
            status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)

#
# Edit key
# GET: access from browser, POST: send request
#
@app.route('/edit_key/<keyid>', methods=['GET'])
@login_required
def edit_key(keyid):
    from server.key.key_mng import keyMgr
    from server.key.key_mng import POLICY_ACTION_LIST
    from server.database.key import KEY_STATUS_CNAME
    log ("Received edit_key request from '%s', method %s" % (request.remote_addr, request.method), TAG, toFile=True)
    login=is_login(request, 
        account_types=[server.database.account.ACCOUNT_TYPE_ADMIN]
    )
    if login:
        if keyid is not None:
            if (DEBUG): logD("get_key %s" % keyid, TAG)
            keyinfo = keyMgr().get_key(keyid)
            if keyinfo is not None:
                status = KEY_STATUS_CNAME[keyinfo.status] if keyinfo.status in KEY_STATUS_CNAME else "Unknown"
                # check signature to be shown
                signature = keyinfo.signature
                if signature is None or len(signature) == 0:
                    signature = "NO SIGNATURE"
                elif keyinfo.validateSignature():
                    signature += "(VALID)"
                else:
                    signature += "(NOT MATCH)"

                return render_template("admin/edit_key.html", 
                    # common
                    login=login, 
                    debug=is_debug_db(), 
                    username=current_username(),
                    key=keyinfo,
                    action_list=POLICY_ACTION_LIST,
                    signature=signature,
                    status=status
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


#
# Add policy for key
#
@app.route('/add_policy/<keyid>', methods=['POST'])
@login_required
def add_policy(keyid):
    from server.key.key_mng import keyMgr
    from server.key.key_mng import POLICY_ACTION_LIST
    from server.login.user_mng import usrMgr
    log ("Received add_policy request from '%s', method %s" % (request.remote_addr, request.method), TAG, toFile=True)
    login=is_login(request, 
        account_types=[server.database.account.ACCOUNT_TYPE_ADMIN]
    )
    if login:
        if keyid is not None:
            jsondata = request.json
            username = jsondata['username'] if 'username' in jsondata else None
            remoteIP = jsondata['remoteIP'] if 'remoteIP' in jsondata else None
            action = jsondata['action'] if 'action' in jsondata else None
            rsa = jsondata['rsa'] if 'rsa' in jsondata else None

            if (DEBUG): logD("jsondata %s " % str(jsondata), TAG)
            
            if username is None or len(username) == 0: # username is required
                resp = get_resp(common.ERR_INVALID_ARGS, "no user name", status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
            elif (remoteIP is None or len(remoteIP) == 0) and (action is None or len(action) == 0) and (rsa is None or len(rsa) == 0):
                # nneed information about remote ip or action or id-rsa
                resp = get_resp(common.ERR_INVALID_ARGS, "Nothing to be changed", status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
            else:
                # check user
                # require user be active first
                userinfo = usrMgr().get_userinfo(username)
                if userinfo is None or userinfo.id is None:
                    resp = get_resp(common.ERR_INVALID_ARGS, "Not found user name %s" % username, status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
                else:
                    if action not in POLICY_ACTION_LIST:
                        resp = get_resp(common.ERR_INVALID_ARGS, "Action %s not support" % action, status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
                    else:
                        res = common.ERR_FAILED
                        msg = ""
                        # add policy
                        log("addPolicy for key %s" % keyid, TAG, True)
                        [res, msg] = keyMgr().addPolicy(keyid, action, userinfo.id, remoteIP, rsa)

                        if (res == common.ERR_NONE): #OK
                            resp = get_resp(0, "add Policy success"  
                                    , status_code=common.ERR_HTTP_RESPONSE_OK)
                        else:
                            resp = get_resp(res, "add Policy failed %d (%s). %s" % 
                                    (res, common.get_err_msg(res), msg), status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)

            if (DEBUG): logD("resp %s" % resp)
            return resp
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

#
# Delete policy
#
@app.route('/del_policy/<keyid>', methods=['POST'])
@login_required
def del_policy(keyid):
    from server.key.key_mng import keyMgr
    from server.key.key_mng import POLICY_ACTION_LIST
    from server.login.user_mng import usrMgr
    log ("Received del_policy request forfrom '%s', method %s" % (request.remote_addr, request.method), TAG, toFile=True)
    login=is_login(request, 
        account_types=[server.database.account.ACCOUNT_TYPE_ADMIN]
    )
    if login:
        if keyid is not None:
            if (DEBUG): logD("delete key %s" % keyid, TAG)
            [res, msg] = keyMgr().delPolicy(keyid)
            if (res == common.ERR_NONE): #OK
                resp = get_resp(0, "delete Policy success"  
                        , status_code=common.ERR_HTTP_RESPONSE_OK)
            else:
                resp = get_resp(res, "delete Policy failed %d (%s). %s" % 
                        (res, common.get_err_msg(res), msg), status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)

            if (DEBUG): logD("resp %s" % resp)
            return resp
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