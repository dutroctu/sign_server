#!/usr/bin/env python
#
#  SIGN FOT TBOX
#
from flask import Flask
from flask_restful import Api, Resource, reqparse
from flask import send_file
from flask import render_template
from flask import request, abort, jsonify, send_from_directory
# import app
from server import common as common
from server.app import app

import os
from server import applog as applog 
from server.applog import log
from server.applog import logD
from server.applog import logE
from datetime import datetime

from server.sign.signreq import SignRequest
from server.sign.signreq import SignTool

from server import common as common
from server.common import DEFAULT as DEFAULT
from server import hash as hash
from server.app import getProjectList
from server.app import getModelList
from server.sign.signresp import SignResp
import server.sign.signfactory
import server.login.session

import zipfile
from io import BytesIO
import shutil
import subprocess
from server.login.login import is_login, current_username
import traceback
import sys
from server.app import ROOT_DIR

from server.sign import signfactory as signfactory
from server.app import DEBUG
# from server.key.key_mng import keyMgr
from server.storage import storageMgr

from server.key.android.app_key_tool import KEY_TOOL_NAME


from server.common import INVALID_KEY_ID

TAG = "signapk"
APK_TOOL_NAME = "apk"
APK_TOOL_DESC = "Sign Android app (apk/bundle)"

# command timeout, to avoid locking server (i.e. key need password, but no password is set)
COMMAND_TIMEOUT_SECOND=30

# SIGNER TOOL
TOOL_APK_SIGNER="apksigner"
TOOL_JAR_SIGNER="jarsigner"

TOOL_LIST = {
    DEFAULT:"Auto select tool",
    TOOL_APK_SIGNER: "Sign with apksigner (apk)",
    TOOL_JAR_SIGNER: "Sign with jarsigner (apk/app bundle)",
}

INPUT_IMAGE_TAG = "image"
# SIGN SCRIPT
TOOL_SIGNER_SCRIPT_FNAME="sign.sh"
TOOL_ANDROID_SDK_TOOL_FOLDER = os.path.join(ROOT_DIR, "tool/android_sdk")

#FIX KEYSTORE/KEY/CERT NAME
KEYSTORE_FNAME_NO_EXT = "androidapp"
KEYSTORE_FNAME = "%s.jks" % KEYSTORE_FNAME_NO_EXT
CERT_FNAME = "androidapp.x509.pem"
KEY_FNAME = "androidapp.pk8"

class SignRequestApk(SignRequest):
    signertool = "" # signer
    key_id = None
    key_info = None
    key_working_folder = None
    def __init__(self, request):
        super(SignRequestApk, self).__init__(request, APK_TOOL_NAME)
        if (DEBUG): logD("request %s" % str(request.form), TAG)
        self.signertool = common.extract_form_request(request, common.PARAM_TOOL)
        self.key_working_folder = None
        [self.key_id, self.key_info] = self.getKeyInfo(request, "key_id", "key_name", KEY_TOOL_NAME)

       
    def toString(self):
        str = super(SignRequestApk, self).toString()
        if (self.signertool is not None):
            str += "tool: %s, " % self.signertool
        str += "\n"
        return str

    # return dic of keyinfo, with key is keytype, value is key_info
    def getListKeyInfo(self):
        return {
            "key_info":self.key_info
            }

class SignApk(SignTool):

    def getName(self, desc=False):
        return APK_TOOL_NAME if not desc else APK_TOOL_DESC

    def parse_request(self, request):
        if (DEBUG): logD("SignApk parse_request")
        return SignRequestApk(request)

    def check(self, __req):
        [__code, __msg] = super(SignApk, self).check(__req)

        if (__code != 0):
            return [__code, __msg]

        __result_str = ""
        __result_code = 0


        if __req.signertool is None or len(__req.signertool) == 0:
            __result_code = -1
            __result_str += "No tool, '%s'?, " % DEFAULT
        else :
            if __req.signertool not in TOOL_LIST:
                __result_code = -1
                __result_str += "tool %s not support, " % (__req.signertool )


        if __result_code == 0 and __req.key_id is None:
            __result_code = -1
            __result_str += "No key_id or key_name"


        if __result_code == 0 and __req.key_id == INVALID_KEY_ID:
            __result_code = -1
            __result_str += "invalid/not exist key_id/name"


        if (__result_code == 0):
            __result_str = "OK"

        return [__result_code, __result_str]

    # Sign apk
    def sign_apk(self, __req):

        # get script to sign
        if not os.path.exists(__req.tool_working_folder):
            logE("%s not found" % __req.tool_working_folder, TAG, True)
            return SignResp(__req, -1, "Not found script to sign")
        
        ks_path=""
        cert_path=""
        key_path=""

        # check key
        if __req.key_working_folder is not None:
            ks_path = os.path.join(__req.key_working_folder, KEYSTORE_FNAME)
            cert_path = os.path.join(__req.key_working_folder, CERT_FNAME)
            key_path = os.path.join(__req.key_working_folder, KEY_FNAME)
            if (DEBUG): logD("ks_path %s" % ks_path)
            if (DEBUG): logD("cert_path %s" % cert_path)
            if (DEBUG): logD("key_path %s" % key_path)
            
            # key is specified, but not found any key, out
            if not (os.path.exists(ks_path) or (os.path.exists(cert_path) and os.path.exists(key_path))):
                logE("not found any key", TAG, True)
                return SignResp(__req, -1, "not found any key to sign")
        else:
            log("Use default key", TAG)
        

        sign_script = os.path.join(__req.tool_working_folder, TOOL_SIGNER_SCRIPT_FNAME)
        if (DEBUG): logD("sign_script %s" % sign_script)

        if (INPUT_IMAGE_TAG not in __req.file_path_list) or __req.file_path_list[INPUT_IMAGE_TAG] == 0:
            return SignResp(__req, -1, "Uploaded file required input type name is '%s'" % INPUT_IMAGE_TAG)

        in_file = __req.file_path_list[INPUT_IMAGE_TAG][0]
        fname = __req.getFileName(INPUT_IMAGE_TAG)
        sign_fname = __req.getSignFile(INPUT_IMAGE_TAG)
        if (in_file is None) or not os.path.exists(in_file):
            return SignResp(__req, -1, "file not found")
        output_file = os.path.join(__req.out_working_folder, sign_fname)

        signed_image_fname = "%s_signed" % fname
        signed_image_folder = os.path.join(__req.out_working_folder, signed_image_fname) # signed file is put in "output" folder

        if not os.path.exists(sign_script):
            logE("%s not found" % sign_script, TAG, True)
            return SignResp(__req, -1, "Not found script to sign")

        # handle "default" case
        tool = __req.signertool
        isAPK = fname.endswith(".apk")
        if tool == DEFAULT: # select tool basing on file extenstion
            if isAPK:
                tool = TOOL_APK_SIGNER
            else:
                tool = TOOL_JAR_SIGNER
        password=None

        # check if key has password, input password to stdin
        if __req.key_info is not None and __req.key_info.pwd is not None and len(__req.key_info.pwd) > 0:
            if (DEBUG): logD("Set password", TAG)
            password = __req.key_info.pwd.encode()
        
        command = "%s --input=%s --output=%s --ks=%s --key=%s --cert=%s --signer=%s" % (
            sign_script, in_file, signed_image_folder, ks_path, key_path, cert_path, tool)
        
        log("Signing script: %s" % sign_script, TAG)
        if (DEBUG): logD ("command: " + str(command), TAG)

        res = 0

        # run signing script
        try:
            import subprocess
            child = subprocess.run(command, shell=True, input=password, timeout=COMMAND_TIMEOUT_SECOND)
            res = child.returncode
        except:
            traceback.print_exc()
            return SignResp(__req, -1, "Sign failed, exception occurs")

        # check result
        if (DEBUG): logD("command %s" % str(res))
        if res != 0 :
            logE("Signed failed with command %s, res %s" % (command, str(res)), TAG, True)
            return SignResp(__req, -1, "Signed failed %s" % str(res))

        resp = self.packOutput(__req, signed_image_folder)

        return resp

    # do signing
    def do_sign(self, __req):
        if (DEBUG): logD("Apk do sign")
        # check/prepare tool
        [__code, __msg] = self.prepareTool(__req, TOOL_ANDROID_SDK_TOOL_FOLDER, False)

        if (__code != common.ERR_NONE):
            return SignResp(__req, __code, __msg)

        # Get key basing on key id, or use default one
        log ("Sign with key: %s" % __req.key_id, TAG, True)
        
        key_dir = os.path.join(__req.out_working_folder, "key")
        if os.path.exists(key_dir):
            if (DEBUG): logD("Remove existing one to create new one")
            common.rmdirs(key_dir)
        common.mkdir(key_dir)

        if (__req.key_id != common.DEFAULT_KEY_ID):
            [__code, __msg] = self.prepareKey(__req, __req.key_info, key_dir)
            if (__code == common.ERR_NONE):
                __req.key_working_folder = key_dir
        else:
            __req.key_working_folder = None # used default key in tool
        
        if (__code != common.ERR_NONE):
            applog.logE("Prepare key failed %d" % __code)
            return SignResp(__req, __code, __msg)
        
        return self.sign_apk(__req)


    # Get template render for webpage used to manual sign
    def get_html_render_for_manual_sign(self, request):
        from server.key.key_mng import keyMgr
        from server.sign import signfactory as signfactory
        key_list = keyMgr().get_all_keys(tool=APK_TOOL_NAME, keytool = KEY_TOOL_NAME)

        return render_template(
            "sign/sign_apk.html"
            # common for headers
            , login=is_login(request)
            , username=current_username()
            # common for sign
            , module="Android application"
            , project_list=getProjectList()
            , model_list=getModelList()
            , key_list=key_list
            , default_key_id=common.DEFAULT_KEY_ID
            # specific
            , apk_sign_tool_list=TOOL_LIST
            )
    
    def getKeyToolList(self):
        return [KEY_TOOL_NAME]
        
    def validate_key(self, key_req, key_dir, keypass, keytoolname=None):
        log("validate_key", TAG)
        if (DEBUG): logD("key_dir %s" % key_dir, TAG)
        need_file = os.path.join(key_dir, KEYSTORE_FNAME)
        if not os.path.exists(need_file):
            logE("Validate key for apk failed, not suitable file name", TAG)
            return [common.ERR_NOT_FOUND, "Not found %s" % KEYSTORE_FNAME]
        
        password=None

        
        # check if key has password, input password to stdin
        if keypass is not None and len(keypass) > 0:
            if (DEBUG): logD("Set password", TAG)
            password = keypass.encode()
        
         # keytool -list -v -keystore androidapp.jks -alias androidapp
        command = "keytool -list -v -keystore %s -alias %s || exit $?" % (
            need_file, KEYSTORE_FNAME_NO_EXT)
        
        res = 0
        if (DEBUG): logD(command, TAG)

        # run signing script
        try:
            import subprocess
            child = subprocess.run(command, shell=True, input=password, timeout=COMMAND_TIMEOUT_SECOND)
            res = child.returncode
        except:
            traceback.print_exc()
            return [common.ERR_EXCEPTION, "check failed, exception occurs"]

        if res != 0 :
            logE("Validate key for apk failed", TAG)
            return [common.ERR_INVALID, "Invalid key"] 
        else:
            log("Validate key for apk OK", TAG)
            return [common.ERR_NONE, "OK"] 
