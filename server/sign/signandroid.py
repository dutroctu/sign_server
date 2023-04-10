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

from server.key.android.platform_key_tool import KEY_TOOL_NAME as PF_KEY_TOOL_NAME
from server.key.android.avb_key_tool import KEY_TOOL_NAME as AVB_KEY_TOOL_NAME
from server.key.android.ota_key_tool import KEY_TOOL_NAME as OTA_KEY_TOOL_NAME


from server.common import INVALID_KEY_ID

TAG = "signandroid"
ANDROID_TOOL_NAME = "android"
ANDROID_TOOL_DESC = "Sign Android images"

# command timeout, to avoid locking server (i.e. key need password, but no password is set)
# COMMAND_TIMEOUT_SECOND=300
COMMAND_TIMEOUT_MIN=30
COMMAND_TIMEOUT_SECOND=(COMMAND_TIMEOUT_MIN*60)

INPUT_IMAGE_TAG = "image"
INPUT_IMAGEX_TAG = "imagex"
# SIGN SCRIPT
TOOL_SIGNER_SCRIPT_FNAME="sign.sh"
TOOL_ANDROID_TOOL_FOLDER = os.path.join(ROOT_DIR, "tool/android_tools")

ANDROID_9="android9"
ANDROID_10="android10"

ANDROID_VERSION_LIST = {
    ANDROID_9:"Android 9 (P)",
    ANDROID_10:"Android 10 (O)"
}
DEFAULT_ANDROID_VER = ANDROID_9

class SignRequestAndroid(SignRequest):
    ota_gen = False
    image_gen = False
    extra_cmd=""
    extra_cmd_ota=""
    version=None
    pf_key_id = None
    pf_key_info = None
    
    avb_key_id = None
    avb_key_info = None
    
    ota_key_id = None
    ota_key_info = None

    pf_key_working_folder = None
    avb_key_working_folder = None
    ota_key_working_folder = None
    def __init__(self, request):
        super(SignRequestAndroid, self).__init__(request, ANDROID_TOOL_NAME)
        if (DEBUG): logD("request %s" % str(request.form), TAG)
        self.ota_gen = common.isCheckParam(request, common.PARAM_OTA)
        self.image_gen = common.isCheckParam(request, common.PARAM_IMAGE)
        self.extra_cmd = common.extract_form_request(request, common.PARAM_COMMAND, default_data="")
        self.extra_cmd_ota = common.extract_form_request(request, "command_ota", default_data="")
        self.version = common.extract_form_request(request, common.PARAM_VERSION, default_data=DEFAULT_ANDROID_VER)

        [self.pf_key_id, self.pf_key_info] = self.getKeyInfo(request, "pf_key_id", "pf_key_name", PF_KEY_TOOL_NAME)
        [self.avb_key_id, self.avb_key_info] = self.getKeyInfo(request, "avb_key_id", "avb_key_name", AVB_KEY_TOOL_NAME)
        [self.ota_key_id, self.ota_key_info] = self.getKeyInfo(request, "ota_key_id", "ota_key_name", OTA_KEY_TOOL_NAME)

        self.pf_key_working_folder = None
        self.avb_key_working_folder = None
        self.ota_key_working_folder = None
       
    def toString(self):
        str = super(SignRequestAndroid, self).toString()
        str += "ota_gen: %d, " % self.ota_gen
        str += "image_gen: %d, " % self.image_gen
        str += "\n"
        return str
    
    # return dic of keyinfo, with key is keytype, value is key_info
    def getListKeyInfo(self):
        return {
            "pf_key_info":self.pf_key_info,
            "avb_key_info":self.avb_key_info,
            "ota_key_info":self.ota_key_info
            }

class SignAndroid(SignTool):

    def getName(self, desc=False):
        return ANDROID_TOOL_NAME if not desc else ANDROID_TOOL_DESC

    def parse_request(self, request):
        if (DEBUG): logD("SignAndroid parse_request")
        return SignRequestAndroid(request)

    def check(self, __req):
        [__code, __msg] = super(SignAndroid, self).check(__req)

        if (__code != 0):
            return [__code, __msg]

        __result_str = ""
        __result_code = 0

        if __req.version is None or len(__req.version) == 0:
            __result_code = -1
            __result_str += "No Android version"
        else :
            if __req.version not in ANDROID_VERSION_LIST:
                __result_code = -1
                __result_str += "version %s not support, " % (__req.version )

        if __result_code == 0 and __req.pf_key_id is None:
            __result_code = -1
            __result_str += "No pf_key_id or pf_key_name"

        if __result_code == 0 and __req.avb_key_id is None:
            __result_code = -1
            __result_str += "No avb_key_id or avb_key_name"

        if __result_code == 0 and __req.ota_key_id is None:
            __result_code = -1
            __result_str += "No ota_key_id or ota_key_name"

        if __req.pf_key_id == INVALID_KEY_ID:
            __result_code = -1
            __result_str += "invalid/not exist pf_key_id/name"

        if __req.avb_key_id == INVALID_KEY_ID:
            __result_code = -1
            __result_str += "invalid/not exist avb_key_id/name"


        if __req.ota_key_id == INVALID_KEY_ID:
            __result_code = -1
            __result_str += "invalid/not exist ota_key_id/name"

        
        if (__result_code == 0):
            __result_str = "OK"

        return [__result_code, __result_str]

    # Sign target file
    def sign_target(self, __req):

        # get script to sign
        if not os.path.exists(__req.tool_working_folder):
            logE("%s not found" % __req.tool_working_folder, TAG, True)
            return SignResp(__req, -1, "Not found script to sign")

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
        imagex_path = os.path.join(__req.in_working_folder, INPUT_IMAGEX_TAG)
        if not os.path.exists(imagex_path):
            imagex_path = ""

        signed_image_fname = "%s_signed" % fname
        signed_image_folder = os.path.join(__req.out_working_folder, signed_image_fname) # signed file is put in "output" folder

        if not os.path.exists(sign_script):
            logE("%s not found" % sign_script, TAG, True)
            return SignResp(__req, -1, "Not found script to sign")

        password=None
        import copy
        new_env = copy.deepcopy(os.environ)
        # check if key has password, input password to environment
        if __req.pf_key_info is not None and __req.pf_key_info.pwd is not None and len(__req.pf_key_info.pwd) > 0:
            if (DEBUG): logD("Set pf password", TAG)
            new_env["ANDROID_PW_VAR"] = __req.pf_key_info.pwd

        if __req.avb_key_info is not None and __req.avb_key_info.pwd is not None and len(__req.avb_key_info.pwd) > 0:
            if (DEBUG): logD("Set pf password", TAG)
            new_env["ANDROID_AVB_PW_VAR"] = __req.avb_key_info.pwd
            
        if __req.ota_key_info is not None and __req.ota_key_info.pwd is not None and len(__req.ota_key_info.pwd) > 0:
            if (DEBUG): logD("Set ota password", TAG)
            new_env["ANDROID_OTA_PW_VAR"] = __req.ota_key_info.pwd
        
        command = "%s %s --input=%s --output=%s --keydir=%s --avbkeydir=%s --otakeydir=%s --extra-cmd=\"%s\"  --extra-cmd-ota=\"%s\" --extra-dir=%s %s %s " % (
            sign_script, # sign script
            "-v" if server.app.DEBUG else "", # show verbose or not
            in_file, # --input
            signed_image_folder, # --output
            __req.pf_key_working_folder if __req.pf_key_working_folder is not None else "", # --keydir
            __req.avb_key_working_folder if __req.avb_key_working_folder is not None else "", # --avbkeydir
            __req.ota_key_working_folder if __req.ota_key_working_folder is not None else "", # --otakeydir
             __req.extra_cmd if __req.extra_cmd is not None else "",  # --extra-cmd
             __req.extra_cmd_ota if __req.extra_cmd_ota is not None else "", # --extra-cmd-ota
            imagex_path, # --extra-dir
             "--ota" if __req.ota_gen else "", 
             "--image" if __req.image_gen else ""
             )
        
        log("Signing script: %s" % sign_script, TAG)
        if (DEBUG): logD ("command: " + str(command), TAG)

        res = 0

        # run signing script
        try:
            import subprocess
            child = subprocess.run(command, shell=True, env=new_env, timeout=COMMAND_TIMEOUT_SECOND if COMMAND_TIMEOUT_SECOND > 0 else None)
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
        if (DEBUG): logD("Android do sign")
        # check/prepare tool
        [__code, __msg] = self.prepareTool(__req, TOOL_ANDROID_TOOL_FOLDER, False)

        if (__code != common.ERR_NONE):
            return SignResp(__req, __code, __msg)

        # Get key basing on key id, or use default one
        log ("Sign with key: %s" % __req.pf_key_id, TAG, True)
        log ("Sign with avb key: %s" % __req.avb_key_id, TAG, True)
        log ("Sign with ota key: %s" % __req.ota_key_id, TAG, True)
        
        pf_key_dir = os.path.join(__req.out_working_folder, "pf_key")
        avb_key_dir = os.path.join(__req.out_working_folder, "avb_key")
        ota_key_dir = os.path.join(__req.out_working_folder, "ota_key")
        
        if __req.pf_key_info != None:
            if os.path.exists(pf_key_dir):
                if (DEBUG): logD("Remove existing pf_key_dir to create new one")
                common.rm_file_in_dir(pf_key_dir)
            else:
                common.mkdir(pf_key_dir)
            if (DEBUG): logD("Prepare platform key", TAG)
            [__code, __msg] = self.prepareKey(__req, __req.pf_key_info, pf_key_dir)
            if (__code == common.ERR_NONE):
                __req.pf_key_working_folder = pf_key_dir
            else:
                logE("Prepare pf key failed", TAG)
        else:
            log("Use default pf key in tools", TAG)
            __code = common.ERR_NONE
        
        if  (__code == common.ERR_NONE) and __req.avb_key_info != None:
            if os.path.exists(avb_key_dir):
                if (DEBUG): logD("Remove existing avb_key_dir to create new one")
                common.rm_file_in_dir(avb_key_dir)
            else:
                common.mkdir(avb_key_dir)
            
            if (DEBUG): logD("Prepare avb key", TAG)
            [__code, __msg] = self.prepareKey(__req, __req.avb_key_info, avb_key_dir)
            if (__code == common.ERR_NONE):
                __req.avb_key_working_folder = avb_key_dir
            else:
                logE("Prepare avb key failed", TAG)
        else:
            log("Use default avb key in tools", TAG)
            __code = common.ERR_NONE
        
        if  (__code == common.ERR_NONE) and __req.ota_key_info != None:
            if os.path.exists(ota_key_dir):
                if (DEBUG): logD("Remove existing ota_key_dir to create new one")
                common.rm_file_in_dir(ota_key_dir)
            else:
                common.mkdir(ota_key_dir)
            
            if (DEBUG): logD("Prepare ota key", TAG)
            [__code, __msg] = self.prepareKey(__req, __req.ota_key_info, ota_key_dir)
            if (__code == common.ERR_NONE):
                __req.ota_key_working_folder = ota_key_dir
            else:
                logE("Prepare ota key failed", TAG)
        else:
            log("Use default ota key in tools", TAG)
            __code = common.ERR_NONE
        
        if (__code != common.ERR_NONE):
            applog.logE("Prepare key failed %d" % __code)
            return SignResp(__req, __code, __msg)
       
        return self.sign_target(__req)


    # Get template render for webpage used to manual sign
    def get_html_render_for_manual_sign(self, request):
        from server.key.key_mng import keyMgr
        from server.sign import signfactory as signfactory
        platform_key_list = keyMgr().get_all_keys(tool=ANDROID_TOOL_NAME, keytool = PF_KEY_TOOL_NAME)
        avb_key_list = keyMgr().get_all_keys(tool=ANDROID_TOOL_NAME, keytool = AVB_KEY_TOOL_NAME)
        ota_key_list = keyMgr().get_all_keys(tool=ANDROID_TOOL_NAME, keytool = OTA_KEY_TOOL_NAME)
        return render_template(
            "sign/sign_android.html"
            # common for headers
            , login=is_login(request)
            , username=current_username()
            # common for sign
            , module="Android Images"
            , project_list=getProjectList()
            , model_list=getModelList()
            , platform_key_list=platform_key_list
            , avb_key_list=avb_key_list
            , ota_key_list=ota_key_list
            , default_key_id=common.DEFAULT_KEY_ID
            , android_versions=ANDROID_VERSION_LIST
            , toolname=ANDROID_TOOL_NAME
            )

    def getKeyToolList(self):
        return [PF_KEY_TOOL_NAME, AVB_KEY_TOOL_NAME, OTA_KEY_TOOL_NAME]
    # def validate_key(self, key_req, key_dir, keypass, keytoolname=None):
    #     log("validate_key", TAG)
    #     if (DEBUG): logD("key_dir %s" % key_dir, TAG)
    #     require_key = [
    #         "media.pk8", "media.x509.pem",
    #         "platform.pk8", "platform.x509.pem",
    #         "releasekey.pk8", "releasekey.x509.pem",
    #         "shared.pk8", "shared.x509.pem",
    #         "verity.pk8", "verity.x509.pem",
    #         ]
        
    #     require_avb_key = [
    #         "keyinfo"
    #     ]
    #     for key in require_key:
    #         if not os.path.exists(os.path.join(key_dir, key)):
    #             logE("Validate key failed, not found %s" % key, TAG)
    #             return [common.ERR_NOT_FOUND, "Not found %s" % key]
        
        
    #     for key in require_avb_key:
    #         if not os.path.exists(os.path.join(key_dir, "avb", key)):
    #             logE("Validate key failed, not found avb %s" % key, TAG)
    #             return [common.ERR_NOT_FOUND, "Not found avb %s" % key]

    #     # TODO: check password???
    #     # TODO: check content of keyinfo???

    #     log("Validate key OK", TAG)
    #     return [common.ERR_NONE, "OK"] 
