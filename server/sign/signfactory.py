#!/usr/bin/env python
#
#  COMMON CLASS FOR SIGN FACTORY
#


from flask import Flask
from flask_restful import Api, Resource, reqparse
from flask import send_file
from flask import render_template
from flask import request, abort, jsonify, send_from_directory
from server.app import app
import os
from server.applog import log
from server.sign.signreq import SignRequest
from server.sign.signtbox import SignTbox
from server.sign.signtbox import TBOX_TOOL_NAME
from server.sign.signtbox import TBOX_TOOL_DESC
from server.sign.signfota import SignFota
from server.sign.signfota import FOTA_TOOL_NAME
from server.sign.signfota import FOTA_TOOL_DESC
from server.sign.signapk import SignApk
from server.sign.signapk import APK_TOOL_NAME
from server.sign.signapk import APK_TOOL_DESC
from server.sign.signandroid import SignAndroid
from server.sign.signandroid import ANDROID_TOOL_NAME
from server.sign.signandroid import ANDROID_TOOL_DESC
from server.sign.signrenesas import SignRenesas
from server.sign.signrenesas import RENESAS_TOOL_NAME
from server.sign.signrenesas import RENESAS_TOOL_DESC
from server.sign.signrenesas_ic import SignRenesasIC
from server.sign.signrenesas_ic import RENESAS_IC_TOOL_NAME
from server.sign.signrenesas_ic import RENESAS_IC_TOOL_DESC
from server.sign.signcommon import SignCommon
from server.sign.signcommon import COMMON_TOOL_NAME
from server.sign.signcommon import COMMON_TOOL_DESC
from server.sign.signprovision import SignProvision
from server.sign.signprovision import TOOL_NAME
from server.sign.signprovision import TOOL_DESC
from server.login.session import SessionMng

from server.sign.signrenesas_dbg import SignRenesasDbg
from server.sign.signrenesas_dbg import RENESAS_DBG_TOOL_NAME
from server.sign.signrenesas_dbg import RENESAS_DBG_TOOL_DESC

from server.sign.signtboxcep import TBOX_CEP_TOOL_NAME,TBOX_CEP_TOOL_DESC, SignToolTBoxCEP

# List of supported signing module
SignModules = {
    TBOX_TOOL_NAME: [SignTbox(), TBOX_TOOL_DESC],
    FOTA_TOOL_NAME: [SignFota(), FOTA_TOOL_DESC],
    APK_TOOL_NAME: [SignApk(), APK_TOOL_DESC],
    ANDROID_TOOL_NAME: [SignAndroid(), ANDROID_TOOL_DESC],
    RENESAS_TOOL_NAME: [SignRenesas(), RENESAS_TOOL_DESC],
    RENESAS_IC_TOOL_NAME: [SignRenesasIC(), RENESAS_IC_TOOL_DESC],
    RENESAS_DBG_TOOL_NAME: [SignRenesasDbg(), RENESAS_DBG_TOOL_DESC],
    COMMON_TOOL_NAME: [SignCommon(), COMMON_TOOL_DESC],
    TOOL_NAME: [SignProvision(), TOOL_DESC],
    TBOX_CEP_TOOL_NAME: [SignToolTBoxCEP(), TBOX_CEP_TOOL_DESC]
    }

#Factory to create corresponding signing module
class SignFactory (object):
    SignRequestList = SessionMng()
    #get sign tool from request
    @staticmethod
    def get_sign_tool(req):
        if (req is not None) and (req.form is not None):
            return SignFactory.get_sign_tool_by_name(req.form.get('project'))
        else:
            return None

    @staticmethod
    def get_sign_tool_by_name(name):
        if (len(name) > 0 and name in SignModules):
            return SignModules[name][0]
        else:
            return None

    # Get list of support module to support signing
    @staticmethod
    def get_sign_tool_list():
        sign_tool_list = {}
        for name, val in SignModules.items():
            sign_tool_list[name] = val[1]
        return sign_tool_list
    
    # get session basing on session id
    @staticmethod
    def getSession(sessionid = None):
        return SignFactory.SignRequestList.get_session(sessionid)

    
    # push session to cache for management
    @staticmethod
    def pushSession(session):
        return SignFactory.SignRequestList.push_session(session)

    # clear session, if session is null, check to clear expired session
    @staticmethod
    def clearSession(session = None):
        if session is None:
            SignFactory.SignRequestList.check_to_clear_session()
        else:
            return SignFactory.SignRequestList.clear_session(session)

    # dump session, if session is null, dump all session
    @staticmethod
    def dumpSession(sessionid = None):
        return SignFactory.SignRequestList.dump(sessionid)
        