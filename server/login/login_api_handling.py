#!/usr/bin/env python
#
#  MANAGE LOGIN 
#

# https://flask-login.readthedocs.io/en/latest/
# https://hackersandslackers.com/flask-login-user-authentication/
# https://www.digitalocean.com/community/tutorials/how-to-add-authentication-to-your-app-with-flask-login
# https://github.com/PrettyPrinted/flask_auth_scotch/blob/master/project/
# https://realpython.com/using-flask-login-for-user-management-with-flask/


from flask import Flask, Blueprint, flash, redirect, url_for,session
from flask_restful import Api, Resource, reqparse
from flask import send_file
from flask import render_template
from flask import request, abort, jsonify, send_from_directory
from server.app import app
import os
from server import common as common
from server.applog import log
from server.applog import logD
from server.applog import logE
from server.app import get_resp
# from server.login.user_mng import UserMgr
# from server.login.user_mng import usrMgr
# from server.login.session import SessionMng
# from server.login.login_info import LoginInfo
# from server.login.login_mng import LoginMgr
from server.common import PARAM_ACCESS_TOKEN
# from flask_login import LoginManager 
from flask_login import login_user, current_user, logout_user, login_required
import json
from server.login.login import login_manager
from server.login.login import auth
from server.login.login import is_login, current_username
from server.app import DEBUG
TAG="login"
# flask login manager

# load login info basing on access token. It's required by flask login, used when access via website
@login_manager.user_loader
def user_loader(token):
    from server.login.login_mng import LoginMgr
    if (DEBUG): logD("user_loader %s" % token)
    return LoginMgr.get_login_info(token)

# load login info basing on request. It's required by flask login, used when access via API
@login_manager.request_loader
def load_user_from_request(request):
    if (DEBUG): logD("load_user_from_request")
    if (DEBUG): logD(str(request.form))
    from server.login.login_mng import LoginMgr
    # FIXME if any thing wrong
    access_token = request.form.get(PARAM_ACCESS_TOKEN)
    # if access_token is None:
    #     # if hasattr(current_user, 'sessionid'):
    #     if isinstance(current_user,LoginInfo):
    #         access_token = current_user.sessionid
    #     else:
    # logD("current_user.sessionid %s" % str(current_user.sessionid))
    if access_token is not None:
        if (DEBUG): logD("access_token %s" % access_token)
        login_info = LoginMgr.get_login_info(access_token)
        if login_info:
            if (DEBUG): logD("ok")
            return login_info
    if (DEBUG): logD("failed")
    return None

# login page
@auth.route('/login')
def login():
    log ("Received login request from '%s', method %s" % (request.remote_addr, request.method), TAG, toFile=True)
    # FIXME: I tried url_value_preprocessor and catch all routes to make common processing, but not success
    # if you find better way, please update this :)
    import server.monitor.system_report
    checkResp = server.monitor.system_report.check_system(request)
    if checkResp is not None:
        return checkResp
        
    return render_template('login.html',messages=request.args.get('messages') if 'messages' in request.args else "")

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.home'))


# receive login request
@auth.route('/login', methods=['POST'])
def login_post():
    log ("Received login post request from '%s', method %s" % (request.remote_addr, request.method), TAG, toFile=True)
    # FIXME: I tried url_value_preprocessor and catch all routes to make common processing, but not success
    # if you find better way, please update this :)
    import server.monitor.system_report
    checkResp = server.monitor.system_report.check_system(request)
    if checkResp is not None:
        return checkResp
        
    from server.login.login_mng import LoginMgr
    # check if it's called by API, via API param in payload
    # TODO: should smarter....
    is_api = False

    # should remember session?
    remember = True if request.form.get(common.PARAM_REMEMBER) else False

    # check param if it's call from API
    if common.PARAM_API in request.form:
        is_api = request.form.get(common.PARAM_API)

    # do login
    [ret, login_info] = LoginMgr.login_with_req(request)

    if ret == common.ERR_NONE and login_info is not None:
        # marked as login in flask login
        login_user(login_info, remember=remember)

        # if not api, redirect to previous page via next argument (flask login)
        if (not is_api):
            next = request.args.get(common.PARAM_NEXT)
            if (DEBUG): logD("next %s" % next if next is not None else "None")
            if not common.is_safe_url(next, request): # valide url if it's safe
                return abort(400) # FIX ME

            return redirect(next or url_for('main.home')) # redidrect to main page
        else:
            return get_resp(200, "OK", {"access_token": login_info.sessionid}) # return access token
    else:
        ret = ret if ret != common.ERR_NONE else common.ERR_FAILED
        if login_info is not None and isinstance(login_info, str):
            messages = login_info
        else:
            messages ="Login failed %d (%s). Wrong username or password? or account is not reay?" % (ret, common.get_err_msg(ret))
        session['messages '] = messages 
        if not is_api: 
            flash('Please check your login details and try again.')
            return redirect(url_for('auth.login',messages=messages)) # failed, redirect to login page again
        else:
            return get_resp(400, messages )
        

#
# Change password
#
@app.route("/changepass", methods=["GET","POST"])
@login_required
def changepass():
    log ("Received changepass request for from '%s', method %s" % (request.remote_addr, request.method), TAG, toFile=True)
    login=is_login(request)
    from server.login.user_mng import usrMgr
    if request.method == 'POST':   
        if login:
            username = common.extract_form_request(request, "username").strip()
            oldPass = common.extract_form_request(request, "oldpassword").strip()
            newPass = common.extract_form_request(request, "newpassword").strip()
            if login:
                if ((username is not None and len(username) > 0)
                    and (oldPass is not None and len(oldPass) > 0) 
                    and (newPass is not None and len(newPass) > 0)):
                    ret = usrMgr().change_password(username, oldPass, newPass)
                else:
                    logE("Invalid input, no userid nor username nor password", TAG)
                    ret = common.ERR_INVALID_ARGS
                
                if (ret == common.ERR_NONE):
                    resp = get_resp(
                        error=0, 
                        message="Change password for user %s successful" % (username), 
                        status_code=common.ERR_HTTP_RESPONSE_OK)
                else:
                    resp = get_resp(
                        error=ret, 
                        message="Failed to change password user %s, ret %d (%s)" % (username, ret, common.get_err_msg(ret)), 
                        status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
            else:
                resp = get_resp(common.ERR_PROHIBIT, "Not login as admin yet", status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
       

        if (DEBUG): logD("resp %s" % resp)
        return resp
    
    #it's GET so return render html to show on browser
    return render_template(
            "user/change_pass.html"
            , login=login
            , username=current_username()
            )

@app.route('/account/<username>', methods=['GET'])
@login_required
def view_account(username):
    from server.login.user_mng import usrMgr
    log ("Received view account request for from '%s', method %s" % (request.remote_addr, request.method), TAG, toFile=True)
    login=is_login(request)
    if username is not None and len(username) > 0 and current_username() == username:
        user_info = usrMgr().get_userinfo(username)
        if (user_info is not None and str(user_info.username) == str(username)):
            signature = user_info.signature
            if signature is None or len(signature) == 0:
                signature = "NO SIGNATURE"
            elif user_info.validateSignature():
                signature += "(VALID)"
            else:
                signature += "(NOT MATCH)"
            #it's GET so return render html to show on browser
            rsa_list = usrMgr().get_rsa(username)
            return render_template(
                    "user/view_user.html"
                    , login=login
                    , username=current_username()
                    , user=user_info
                    , signature=signature
                    , rsa_list=rsa_list if rsa_list is not None else {}
                    )
        else:
            return get_resp(common.ERR_INVALID_ARGS, "Not found username %s" % username, status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
    else:
        return get_resp(common.ERR_INVALID_ARGS, "Invalid user name or not allow to view", status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)

@app.route("/add_rsa", methods=["POST"])
@login_required
def add_rsa():
    from server.login.user_mng import usrMgr
    log ("Received add_rsa request from '%s', method %s" % (request.remote_addr, request.method), TAG, toFile=True)
    jsondata = request.json
    userid = jsondata['userid'] if 'userid' in jsondata else None
    rsa = jsondata['rsa'] if 'rsa' in jsondata else None
    login=is_login(request)

    if login:
        if userid is not None and rsa is not None and len(rsa) > 0 and len(userid) > 0:
            # well done, do it
            [ret, user_info] = usrMgr().add_rsa(userid, rsa)
        else:
            logE("Invalid input, no userid nor rsa", TAG)
            ret = common.ERR_INVALID_ARGS
        if (ret == common.ERR_NONE):
            return get_resp(
                error=0, 
                message="add rsa successful", 
                status_code=common.ERR_HTTP_RESPONSE_OK)
        else:
            return get_resp(
                error=ret, 
                message="Failed to add rsa ret %d (%s)" % (ret, common.get_err_msg(ret)), 
                status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
    else:
        return get_resp(common.ERR_PROHIBIT, "Not login as admin yet", status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)



@app.route("/del_rsa", methods=["POST"])
@login_required
def del_rsa():
    from server.login.user_mng import usrMgr
    log ("Received del_rsa request from '%s', method %s" % (request.remote_addr, request.method), TAG, toFile=True)
    jsondata = request.json
    userid = jsondata['userid'] if 'userid' in jsondata else None
    rsa = jsondata['rsa'] if 'rsa' in jsondata else None
    login=is_login(request)

    if login:
        if userid is not None and rsa is not None and len(rsa) > 0 and len(userid) > 0:
            # well done, do it
            [ret, user_info] = usrMgr().del_rsa(userid, rsa)
        else:
            logE("Invalid input, no userid nor rsa", TAG)
            ret = common.ERR_INVALID_ARGS
        if (ret == common.ERR_NONE):
            return get_resp(
                error=0, 
                message="del rsa successful", 
                status_code=common.ERR_HTTP_RESPONSE_OK)
        else:
            return get_resp(
                error=ret, 
                message="Failed to del rsa ret %d (%s)" % (ret, common.get_err_msg(ret)), 
                status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
    else:
        return get_resp(common.ERR_PROHIBIT, "Not login as admin yet", status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
