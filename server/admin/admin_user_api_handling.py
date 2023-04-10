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
TAG = "adminuser"
#
# list of user
# ADMIN account only
#
@app.route('/users', methods=['GET','POST'])
@login_required
def list_users():
    from server.login.user_mng import usrMgr
    # only allow admin user
    login=is_login(request, database.account.ACCOUNT_TYPE_ADMIN)
    log ("Received user list request from '%s', method %s" % (request.remote_addr, request.method), TAG, toFile=True)

    # get all user, include user marked as deleted
    users = usrMgr().get_all_users(includeDelete=True)
    if request.method == 'POST':   
        if login:
            # FIXME?
            resp = get_resp(200, "OK", {"user_list": users})
        else:
            resp = get_resp(common.ERR_PROHIBIT, "Not login as admin yet", status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
        return resp
    for user in users:
        if (DEBUG): logD("User: %s" % user.toString())
    #it's GET so return render html to show on browser
    return render_template(
            "admin/users.html"
            , login=login
            , user_list=users
            , username=current_username()
            )

#
# Add new user
# ADMIN account only
#
@app.route('/add_user', methods=['GET','POST'])
@login_required
def add_user():
    from server.login.user_mng import usrMgr
    from server.login.add_user import AddUserRequest
    log ("Received add user request for from '%s', method %s" % (request.remote_addr, request.method), TAG, toFile=True)
    login=is_login(request, database.account.ACCOUNT_TYPE_ADMIN)
    # POST request, mean request from client or data is submited
    if request.method == 'POST':   
        if login:
            res = common.ERR_FAILED
            resp = get_resp(common.ERR_FAILED, "Unknown error", status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
            # parse requests
            __req = AddUserRequest()
            [__code, __msg]  = __req.parse(request)

            if __code != common.ERR_NONE:
                logE("Parse request failed")
                resp = get_resp(__code, __msg, status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
            else:
                # check if account exist first
                is_exist = usrMgr().is_username_exist(__req.user_info.username)
                if (is_exist != common.ERR_NOT_FOUND): # not found account, 
                    logE("User %s already exist" % __req.user_info.username)
                    resp = get_resp(0, "Account %s already existed" % ( __req.user_info.username), status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
                else:
                    log("Add user %s" % __req.user_info.username, toFile=True)
                    if (DEBUG): logD("user_info %s" % __req.user_info.toString())

                    # all seem well, create new account
                    [res, user_info] = usrMgr().create_account2(__req.user_info)

                if (res == common.ERR_NONE): #OK
                    resp = get_resp(0, "Create user %s OK, default password: %s" % ( __req.user_info.username, user_info.raw_password), status_code=common.ERR_HTTP_RESPONSE_OK)
                else:
                    resp = get_resp(res, "Create user failed faid %d (%s)" % (res, common.get_err_msg(res)), status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
        else:
            resp = get_resp(common.ERR_PROHIBIT, "Not login as admin yet", status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
       

        if (DEBUG): logD("resp %s" % resp)
        return resp
    
    #it's GET so return render html to show on browser
    return render_template(
            "admin/add_user.html"
            , login=login
            , username=current_username()
            , account_type=database.account.ACCOUNT_TYPE_ID_CNAME
            )

#
# Activate/Deactive account
# Admin only
#
@app.route("/activate_user", methods=["POST"])
@login_required
def activate_user():
    from server.login.user_mng import usrMgr
    log ("Received activate_user request from '%s', method %s" % (request.remote_addr, request.method), TAG, toFile=True)
    jsondata = request.json
    userid = jsondata['userid'] if 'userid' in jsondata else None
    username = jsondata['username'] if 'username' in jsondata else None
    activate = jsondata['activate'] if 'activate' in jsondata else None
    login=is_login(request, database.account.ACCOUNT_TYPE_ADMIN)


    if login:
        if userid is not None and username is not None:
            # well done, do it
            [ret, user_info] = usrMgr().activate_account(username,userid, activate)
        else:
            logE("Invalid input, no userid nor username", TAG)
            ret = common.ERR_INVALID_ARGS
        if (ret == common.ERR_NONE):
            return get_resp(
                error=0, 
                message="%s user %s successful" % ("Activate" if activate else "Deactivate", username), 
                status_code=common.ERR_HTTP_RESPONSE_OK)
        else:
            return get_resp(
                error=ret, 
                message="Failed to activate/deactive user %s, ret %d (%s)" % (username, ret, common.get_err_msg(ret)), 
                status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
    else:
        return get_resp(common.ERR_PROHIBIT, "Not login as admin yet", status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)

#
# Reset password of account
# Admin only
#
@app.route("/resetpass", methods=["POST"])
@login_required
def reset_password():
    from server.login.user_mng import usrMgr
    log ("Received reset_password request from '%s', method %s" % (request.remote_addr, request.method), TAG, toFile=True)
    jsondata = request.json
    userid = jsondata['userid'] if 'userid' in jsondata else None
    username = jsondata['username'] if 'username' in jsondata else None
    login=is_login(request, database.account.ACCOUNT_TYPE_ADMIN)

    if login:
        if userid is not None and username is not None:
            [ret, user_info] = usrMgr().reset_password(username,userid)
        else:
            logE("Invalid input, no userid nor username", TAG)
            ret = common.ERR_INVALID_ARGS
        if (ret == common.ERR_NONE):
            return get_resp(
                error=0, 
                message="Reset password for user %s successful, password: %s" % (user_info.username, user_info.raw_password), 
                status_code=common.ERR_HTTP_RESPONSE_OK)
        else:
            return get_resp(
                error=ret, 
                message="Failed to rest password user %s, ret %d (%s)" % (username, ret, common.get_err_msg(ret)), 
                status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
    else:
        return get_resp(common.ERR_PROHIBIT, "Not login as admin yet", status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)

#
# delete user
# Admin only
#
@app.route("/delete_user", methods=["POST"])
@login_required
def delete_user():
    from server.login.user_mng import usrMgr
    log ("Received delete_user request from '%s', method %s" % (request.remote_addr, request.method), TAG, toFile=True)
    jsondata = request.json
    userid = jsondata['userid'] if 'userid' in jsondata else None
    username = jsondata['username'] if 'username' in jsondata else None
    force = jsondata['force'] if 'force' in jsondata else None # force delete or mark delete only?
    login=is_login(request, database.account.ACCOUNT_TYPE_ADMIN)
    if login:
        if userid is not None and username is not None:
            ret = usrMgr().delete_account(username,userid, force==1)
        else:
            logE("Invalid input, no userid nor username", TAG)
            ret = common.ERR_INVALID_ARGS
        if (ret == common.ERR_NONE):
            return get_resp(
                error=0, 
                message="Delete user %s successful" % (username), 
                status_code=common.ERR_HTTP_RESPONSE_OK)
        else:
            return get_resp(
                error=ret, 
                message="Failed to delete user %s, ret %d (%s)" % (username, ret, common.get_err_msg(ret)), 
                status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
    else:
        return get_resp(common.ERR_PROHIBIT, "Not login as admin yet", status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)

#
# Edit user info
#
@app.route('/edit_user/<userid>', methods=['GET','POST'])
@login_required
def edit_user(userid):
    from server.login.user_mng import usrMgr
    from server.login.add_user import AddUserRequest
    log ("Received edit user request for from '%s', method %s" % (request.remote_addr, request.method), TAG, toFile=True)
    login=is_login(request, database.account.ACCOUNT_TYPE_ADMIN)

    if login:
        if userid is not None:
            user_info = usrMgr().get_user_from_id(userid)
            if (user_info is not None and str(user_info.id) == str(userid)):
                # POST request, mean request from client or data is submited
                if request.method == 'POST':   
                    res = common.ERR_FAILED
                    resp = get_resp(common.ERR_FAILED, "Unknown error", status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
                    # parse sign requests
                    __req = AddUserRequest()

                    [__code, __msg]  = __req.parse(request)

                    if __code != common.ERR_NONE:
                        logE("Parse request failed", TAG)
                        resp = get_resp(__code, __msg, status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
                    else:
                        __req.user_info.id = userid.strip()

                        # check if user exist
                        is_exist = usrMgr().is_userid_exist(__req.user_info.id)

                        if (is_exist == common.ERR_EXISTED):
                            log("update user %s" % __req.user_info.username, toFile=True)
                            if (DEBUG): logD("user_info %s" % __req.user_info.toString())

                            res = usrMgr().updateUserInfo(__req.user_info)

                            if (res == common.ERR_NONE): #OK
                                resp = get_resp(0, "Edit user %s OK" % (userid), status_code=common.ERR_HTTP_RESPONSE_OK)
                            else:
                                resp = get_resp(res, "Edit user failed %d (%s)" % (res, common.get_err_msg(res)), status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)

                        else:
                            logE("User %s not found exist" % userid)
                            resp = get_resp(is_exist, "Userid %s not found" % ( userid), status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)

                    if (DEBUG): logD("resp %s" % resp)
                    return resp
                
                #it's GET so return render html to show on browser
                return render_template(
                        "admin/edit_user.html"
                        , login=login
                        , username=current_username()
                        , user=user_info
                        , account_type=database.account.ACCOUNT_TYPE_ID_CNAME
                        )
            else:
                return get_resp(common.ERR_INVALID_ARGS, "Not found userid %s" % userid, status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
        else:
            return get_resp(common.ERR_INVALID_ARGS, "Invalid user id", status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
    else:
        return get_resp(common.ERR_PROHIBIT, "Not login with proper account", status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)

#
# View user info
#
@app.route('/user/<userid>', methods=['GET'])
@login_required
def view_user(userid):
    from server.login.user_mng import usrMgr
    log ("Received view user request for from '%s', method %s" % (request.remote_addr, request.method), TAG, toFile=True)
    login=is_login(request, database.account.ACCOUNT_TYPE_ADMIN)
    if login:
        if userid is not None:
            user_info = usrMgr().get_user_from_id(userid)
            if (user_info is not None and str(user_info.id) == str(userid)):
                signature = user_info.signature
                if signature is None or len(signature) == 0:
                    signature = "NO SIGNATURE"
                elif user_info.validateSignature():
                    signature += "(VALID)"
                else:
                    signature += "(NOT MATCH)"
                
                # get rsa list
                rsa_list = usrMgr().get_rsa(userid=userid)

                return render_template(
                        "admin/user.html"
                        , login=login
                        , username=current_username()
                        , user=user_info
                        , signature=signature
                        , rsa_list=rsa_list if rsa_list is not None else {}
                        )
            else:
                return get_resp(common.ERR_INVALID_ARGS, "Not found userid %s" % userid, status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
        else:
            return get_resp(common.ERR_INVALID_ARGS, "Invalid user id", status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
    else:
        return get_resp(common.ERR_PROHIBIT, "Not login with proper account", status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)

