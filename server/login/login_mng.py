#!/usr/bin/env python
#
#  LOGIN MANAGEMENT
#


from flask import Flask
from flask_restful import Api, Resource, reqparse
from flask import send_file
from flask import render_template
from flask import request, abort, jsonify, send_from_directory
from server.app import app
from server.common import PARAM_USERNAME
from server.common import PARAM_PASSWORD
import os
from server import common as common
from server.applog import log
from server.applog import logD
from server.applog import logE
from server.applog import Log
from server.app import get_resp
from server.login.user_mng import UserMgr
from server.login.user_mng import usrMgr
from server.login.session import SessionMng
from server.login.login_info import LoginInfo
from server.app import DEBUG
TAG="login"

logit = Log(TAG)

# Login management
class LoginMgr (object):
    LoginSessionList = SessionMng()
    LoginInfoList = {}

    # get login info basing on assess token, for authenticated login only
    @staticmethod
    def get_login_info(access_token):
        if (DEBUG): logD("access_token %s" % access_token)
        if (access_token is not None):
            access_token = access_token.strip()
            if len(access_token) > 0 and access_token in LoginMgr.LoginInfoList:
                login_info = LoginMgr.LoginInfoList[access_token]
                
                if (login_info is not None) and (login_info.is_active and login_info.is_authenticated):
                    return login_info

        return None

    # check login
    @staticmethod
    def check_login(req):
        if (DEBUG): logD("check_login ")
        if (req is not None) and (req.form is not None) and (common.PARAM_ACCESS_TOKEN in req.form):
            login_info = LoginMgr.get_login_info(req.form.get(common.PARAM_ACCESS_TOKEN))
            if (login_info is not None):
                if (    (login_info.remoteIP is None or login_info.remoteIP == req.remote_addr) and 
                        ((login_info.remotePort is None) or 
                            (( login_info.remotePort is not None) and (login_info.remotePort == req.environ.get('REMOTE_PORT')))
                        )
                    ):
                    return login_info
        return None
    
    # check to clean login session
    @staticmethod
    def check_and_clean_login_session(access_token = None): #if access_token is None, check whole
        if (access_token is not None) and (access_token in LoginMgr.LoginInfoList):
            login_info = LoginMgr.LoginInfoList.pop(access_token)
            # TODO: async processing?
            if (login_info is not None):
                LoginMgr.clearSession(login_info.sessionid)

    # do login
    @staticmethod
    def login_with_req(req):
        requester = "%s:%s" % (req.remote_addr, req.environ.get('REMOTE_PORT'))
        logit.i("login_with_req from %s" % requester, True)
        # log("login_with_req from %s" % requester, TAG, True)
        if (req is not None) and (req.form is not None) and (PARAM_USERNAME in req.form) and (PARAM_PASSWORD in req.form):
            # TODO: is it safe?
            # FIXME: is it safe?
            username = req.form.get(PARAM_USERNAME) # require user name and password
            password = req.form.get(PARAM_PASSWORD) # require user name and password

            if (username is not None) and len(username) > 0 and (password is not None) and len(password) > 0:
                # check if acc exist
                [ret, userinfo] = usrMgr().check_account(username, password, requester=requester)
                log("login result %d" % ret)

                # ok
                if (ret == common.ERR_NONE and userinfo is not None):
                    if (DEBUG): logD("userinfo %s" % userinfo.toString())
                    if (userinfo.is_active()): # user is active
                        # build login session
                        session = LoginMgr.getSession()

                        if (session is not None and session.uuid is not None):
                            session.set_data(userinfo)
                            login_info = LoginInfo()
                            login_info.sessionid = session.uuid
                            login_info.username = username
                            login_info.fullname = userinfo.fullname
                            login_info.userid = userinfo.id
                            login_info.type = userinfo.type
                            login_info.remoteIP = req.remote_addr
                            login_info.remotePort = req.environ.get('REMOTE_PORT')
                            login_info.login_time = common.current_time()
                            login_info.last_active_time = login_info.login_time 
                            LoginMgr.LoginInfoList[login_info.sessionid] = login_info
                            login_info.is_authenticated = True
                            login_info.is_active = True
                            LoginMgr.pushSession(session)
                            log("Login %s ok" % login_info.username, TAG, False)
                            return [common.ERR_NONE, login_info ]
                        else:
                            logE("Login %s failed, invalid session" % username, toFile=False)
                            return [common.ERR_INVALID, "Invalid session"]
                    else:
                        logE("Login %s failed, account is inactive" % username, toFile=False)
                        return [common.ERR_INACTIVE, "account is inactive"]
                else:
                    ret = ret if ret != common.ERR_NONE else common.ERR_FAILED
                    if ret == common.ERR_LOCKED:
                        msg = "Account is locked"
                    else:
                        msg = "Login %s failed, account not found or user name/pass not match, or account not ready, ret %d" % (username, ret)
                    logit.e(msg, toFile=False)
                    # log(msg, TAG, toFile=False)
                    return [ret, msg]
            else:
                logit.e("Login %s failed, username/pass is invalid" % username, toFile=False)
                # log("Login %s failed, username/pass is invalid" % username, TAG, toFile=False)
                return [common.ERR_INVALID, "username/pass is invalid"]
        else:
            logit.e("Login failed, invalid rquest", toFile=False)
            # log("Login failed, invalid rquest", TAG, toFile=False)
            return [common.ERR_INVALID_DATA, "invalid rquest"]

    # loging with user name and password
    @staticmethod
    def login_with_user(username, password):
        logit.e("login %s"  % username, True)
        # log("login %s"  % username, TAG, True)
        if (username is not None) and len(username) > 0 and (password is not None) and len(password) > 0:
            # get user account
            [ret, userinfo] = usrMgr().check_account(username, password)
            if (DEBUG): logD("login result %d" % ret)
            if (ret == common.ERR_NONE and userinfo is not None):
                if (DEBUG): logD("userinfo %s" % userinfo.toString())
                if (userinfo.is_active()):
                    # build loging session
                    session = LoginMgr.getSession()
                    if (session is not None and session.uuid is not None):
                        session.set_data(userinfo)
                        login_info = LoginInfo()
                        login_info.sessionid = session.uuid
                        login_info.username = username
                        login_info.fullname = userinfo.fullname
                        login_info.userid = userinfo.id
                        login_info.login_time = common.current_time()
                        login_info.last_active_time = login_info.login_time 
                        LoginMgr.LoginInfoList[login_info.sessionid] = login_info
                        login_info.is_authenticated = True
                        login_info.is_active = True
                        LoginMgr.pushSession(session)
                        log("Login %s ok" % login_info.username, TAG, True)
                        return [common.ERR_NONE, login_info ]
                    else:
                        logE("Login %s failed, invalid session" % username, TAG, True)
                        return [common.ERR_INVALID, "Invalid session"]
                else:
                    logE("Login %s failed, account is inactive" % username, TAG, True)
                    return [common.ERR_INACTIVE, "account is inactive"]
            else:
                logE("Login %s failed, account not found or user name/pass not match, or account not active" % username, TAG, True)
                return [common.ERR_NOT_FOUND, "account not found"]
        else:
            logE("Login %s failed, username/pass is invalid" % username, TAG, True)
            return [common.ERR_INVALID, "username/pass is invalid"]
                
    # get session basing on session id
    @staticmethod
    def getSession(sessionid = None):
        return LoginMgr.LoginSessionList.get_session(sessionid)

    
    # push session to cache for management
    @staticmethod
    def pushSession(session):
        return LoginMgr.LoginSessionList.push_session(session)

    # clear session, if session is null, check to clear expired session
    @staticmethod
    def clearSession(sessionid = None):
        if sessionid is None:
            LoginMgr.LoginSessionList.check_to_clear_session()
        else:
            return LoginMgr.LoginSessionList.clear_session(sessionid)

    # dump session, if session is null, dump all session
    @staticmethod
    def dumpSession(sessionid = None):
        return LoginMgr.LoginSessionList.dump(sessionid)
        