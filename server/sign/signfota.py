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
from server.app import DEBUG
from server import common as common
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

from server.fota.fotagentool import TOOL_FOTA_FOLDER
from server.fota.fotagentool import TOOL_FOTA_FOLDER_ZIP
from server.fota.fotagentool import TOOL_FOTA_SIGN_SCRIPT
from server.fota.fotagentool import TOOL_FOTA_OEM_KEY
from server.fota.fotagentool import TOOL_FOTA_PRIV_KEY
from server.fota.fotagentool import TOOL_FOTA_PUB_KEY
from server.fota.fotagentool import TOOL_FOTA_KEY_DIR_NAME
from server.fota.fotagentool import TOOL_FOTA_PRIV_KEY_REL_PATH
from server.fota.fotagentool import TOOL_FOTA_PUB_KEY_REL_PATH
from server.fota.fotagentool import TOOL_FOTA_SIGN_SCRIPT_REL_PATH
from server.fota.fotagentool import TOOL_FOTA_PRIV_KEY_FNAME
from server.fota.fotagentool import TOOL_FOTA_PUB_KEY_FNAME
from server.fota.fotagentool import TOOL_FOTA_OEM_KEY_REL_PATH
from server.fota.fotagentool import TOOL_FOTA_OEM_KEY_FNAME

# from server.key.key_mng import keyMgr
from server.storage import storageMgr
from server.sign import signfactory as signfactory

from server.key.vinfast.fota_sign_key_tool import KEY_TOOL_NAME as SIGN_KEY_TOOL_NAME
from server.key.vinfast.fota_enc_key_tool import KEY_TOOL_NAME as ENC_KEY_TOOL_NAME

from server.common import INVALID_KEY_ID

TAG = "signfota"

FOTA_TOOL_NAME = "fota"
FOTA_TOOL_DESC = "Sign FOTA package"

TYPE_LIST = [
    "encrypt", # Encrypt file
    "sign", # sign file
    # "encrypt_sign" # TODO: to be supported
    ]

ALGO_AES256_CBC="enc-aes-256-cbc"
ALGO_LIST = [
    ALGO_AES256_CBC, # TODO: add more
    ]

DEFAULT_ALGO=ALGO_AES256_CBC

INPUT_IMAGE_TAG = "image"

class SignRequestFota(SignRequest):
    type = ""
    algo = ""
    is_separate = 0

    enc_key_id = None
    enc_key_info = None

    sign_key_id = None
    sign_key_info = None
    key_working_folder = None

    def __init__(self, __request):
        super(SignRequestFota, self).__init__(__request, FOTA_TOOL_NAME)

        self.type = request.form.get(common.PARAM_TYPE)
        self.algo = request.form.get(common.PARAM_ALG_ID) if common.PARAM_ALG_ID in request.form else DEFAULT_ALGO
        self.is_separate = request.form.get(common.PARAM_IS_SEPARATE, type=int)

        [self.enc_key_id, self.enc_key_info] = self.getKeyInfo(request, "enc_key_id", "enc_key_name", ENC_KEY_TOOL_NAME)
        [self.sign_key_id, self.sign_key_info] = self.getKeyInfo(request, "sign_key_id", "sign_key_name", SIGN_KEY_TOOL_NAME)

        self.key_working_folder = None


    # file name of output signed file
    def getSignFile(self, tag):
        # TODO: support multi files
        if (tag is not None and tag in self.file_path_list) and len(self.file_path_list[tag]) > 0:
            fname = os.path.basename(self.file_path_list[tag][0])
            __tmp = os.path.splitext(fname)
            filename_sign = "%s_%s%s" %(__tmp[0], self.type, __tmp[1])
            return filename_sign
        return None
        
    def toString(self):
        str = super(SignRequestFota, self).toString()
        if (self.type is not None):
            str += "type: %s, " % self.type
        if (self.algo is not None):
            str += "algo: %s, " % self.algo
        str += "is_separate: %s, " % (self.is_separate != 0)
        str += "\n"
        return str

    # return dic of keyinfo, with key is keytype, value is key_info
    def getListKeyInfo(self):
        return {
            "enc_key_info":self.enc_key_info,
            "sign_key_info":self.sign_key_info
            }

class SignFota(SignTool):

    def getName(self, desc=False):
        return FOTA_TOOL_NAME if not desc else FOTA_TOOL_DESC

    def parse_request(self, request):
        if (DEBUG): logD("SignFota parse_request")
        return SignRequestFota(request)

    def check(self, __req):
        [__code, __msg] = super(SignFota, self).check(__req)

        if (__code != 0):
            return [__code, __msg]

        __result_str = ""
        __result_code = 0

        # algorithm
        # TODO: should check here? 
        # if __req.algo is None or len(__req.algo) == 0:
        #     __result_code = -1
        #     __result_str += "No algo, "
        # else :
        #     if __req.algo not in ALGO_LIST:
        #         __result_code = -1
        #         __result_str += "algo %s not support, " % (__req.algo )

        # type like sign/encrypt, etc.
        if __req.type is None or len(__req.type) == 0:
            __result_code = -1
            __result_str += "No type, "
        else :
            if __req.type not in TYPE_LIST:
                __result_code = -1
                __result_str += "type %s not support, " % (__req.type )
                

        if __result_code == 0 and __req.enc_key_id is None:
            __result_code = -1
            __result_str += "No enc_key_id or enc_key_name"


        if __result_code == 0 and __req.sign_key_id is None:
            __result_code = -1
            __result_str += "No sign_key_id or sign_key_name"


        if __result_code == 0 and __req.enc_key_id == INVALID_KEY_ID:
            __result_code = -1
            __result_str += "invalid/not exist enc_key_id/name"

        if __result_code == 0 and __req.sign_key_id == INVALID_KEY_ID:
            __result_code = -1
            __result_str += "invalid/not exist sign_key_id/name"


        if (__result_code == 0):
            __result_str = "OK"

        return [__result_code, __result_str]

    # encrypt or sign file
    def encryptOrSign(self, __req):

        # get script to sign
        if not os.path.exists(__req.tool_working_folder):
            logE("%s not found" % __req.tool_working_folder, TAG, True)
            return SignResp(__req, -1, "Not found script to sign")
        
        oem_key = os.path.join(__req.key_working_folder, TOOL_FOTA_OEM_KEY_FNAME)
        priv_key = os.path.join(__req.key_working_folder, TOOL_FOTA_PRIV_KEY_FNAME)
        public_key = os.path.join(__req.key_working_folder, TOOL_FOTA_PUB_KEY_FNAME)
        sign_script = os.path.join(__req.tool_working_folder, TOOL_FOTA_SIGN_SCRIPT_REL_PATH)
        if (DEBUG): logD("oem_key %s" % oem_key)
        if (DEBUG): logD("priv_key %s" % priv_key)
        if (DEBUG): logD("public_key %s" % public_key)
        if (DEBUG): logD("sign_script %s" % sign_script)
        # check oem key to do encrypt
        if not os.path.exists(oem_key):
            logE("oem key not found", TAG, True)
            return SignResp(__req, -1, "Not found oemkey to sign")

        if (INPUT_IMAGE_TAG not in __req.file_path_list) or __req.file_path_list[INPUT_IMAGE_TAG] == 0:
            return SignResp(__req, -1, "Uploaded file required input type name is '%s'" % INPUT_IMAGE_TAG)

        in_file = __req.file_path_list[INPUT_IMAGE_TAG][0]
        sign_fname = __req.getSignFile(INPUT_IMAGE_TAG)
        if (in_file is None) or not os.path.exists(in_file):
            return SignResp(__req, -1, "file not found")
        output_file = os.path.join(__req.out_working_folder, sign_fname)

        # python3.6 ../../$SIGN_TOOL_PATH/FOTAEncryptSigning.py --enc-aes-256-cbc -oemk ../../$SIGN_TOOL_PATH/oemkey \
        #                                    -inf ./XGW_$XGW_VER.bin.raw -o ./XGW_$XGW_VER.bin
        # python3.6 $SIGN_TOOL_PATH/FOTAEncryptSigning.py -oemk $SIGN_TOOL_PATH/oemkey \
        #                                                 -inf .output_gen/${FOTA_PACKAGE_NAME} \
        #                                                 -prk $SIGN_TOOL_PATH/sign_private.pem \
        #                                                 -pbk $SIGN_TOOL_PATH/fota_public.pem \
        #                                                 -o .output_gen/${FOTA_PACKAGE_ENC_NAME}
        # command to run
        # script 
        if (__req.type == "encrypt"):
            command = "python3 %s --%s -oemk %s -inf %s -o %s" % \
                (sign_script, __req.algo, oem_key, in_file, output_file)
        else :
            if (__req.type == "sign"):
                command = "python3 %s -oemk %s -inf %s -prk %s -pbk %s -o %s" % \
                    (sign_script, oem_key, in_file, priv_key, public_key, output_file)
            else:
                return SignResp(__req, -1, "type not suport %s" % __req.type)

        log ("command: " + command, TAG, True)
        # start signing
        __res = os.system(command)
        if __res != 0 :
            logE("Signed failed with command %s, res %d" % (command, __res), TAG, True)
            return SignResp(__req, -1, "Signed failed %d" % __res)

        if not os.path.exists(output_file):
            logE("output %s not found" % output_file, TAG, True)
            return SignResp(__req, -1, "Not found output")

        # calculate checksum of raw file
        checksum_filename = "%s.md5" % os.path.basename(in_file)
        checksum_path = os.path.join(__req.out_working_folder, checksum_filename)
        raw_hash = hash.md5file(in_file)
        if (raw_hash is not None):
            if common.write_to_file(checksum_path, bytes(raw_hash, 'utf-8')):
                __resp = SignResp(__req, 0, "OK")
                # copy file to download folder
                if __resp.copy_to_download(sign_fname, output_file):
                    if __resp.copy_to_download(checksum_filename, checksum_path):
                        __req.session.set_data(__resp) # all well
                    else: # faile to copy
                        applog.logE("Failed to copy %s" % checksum_filename)
                        __resp.set_response_msg(-2, "failed to copy file for download")
                else: # failed to copy
                    applog.logE("Failed to copy %s" % output_file)
                    __resp.set_response_msg(-2, "failed to copy file for download")
                
                return __resp
            else:
                applog.logE("Failed to save %s" % in_file)
                return SignResp(__req, -1, "Cannot generate md5 for output")
        else:
            applog.logE("Failed to generate checksum of %s" % in_file)
            return SignResp(__req, -1, "Cannot generate md5 for output")

    # do signing
    def do_sign(self, __req):
        if (DEBUG): logD("Fota do sign")
        # extract tool to output folder
        [__code, __msg] = self.prepareTool(__req, TOOL_FOTA_FOLDER_ZIP)

        if (__code != common.ERR_NONE):
            return SignResp(__req, __code, __msg)

        # Get key basing on key id, or use default one
        log ("Sign with enc key: %s" % __req.enc_key_id, TAG, True)
        log ("Sign with sign key: %s" % __req.sign_key_id, TAG, True)
        
        key_dir = os.path.join(__req.tool_working_folder, TOOL_FOTA_KEY_DIR_NAME)

        if (__req.sign_key_info is not None):
            priv_key = os.path.join(key_dir, TOOL_FOTA_PRIV_KEY_FNAME)
            pub_key = os.path.join(key_dir, TOOL_FOTA_PUB_KEY_FNAME)

            if os.path.exists(priv_key):
                if (DEBUG): logD("Remove existing %s to create new one" % priv_key)
                common.rmdirs(priv_key)
            
            if os.path.exists(pub_key):
                if (DEBUG): logD("Remove existing %s to create new one" % pub_key)
                common.rmdirs(pub_key)
            
            [__code, __msg] = self.prepareKey(__req, __req.sign_key_info, key_dir)
            if (DEBUG): logD("prepareKey sign_key_id ret %d - %s" % (__code, __msg))


        if (__code == common.ERR_NONE and __req.enc_key_info is not None):
            oem_key = os.path.join(key_dir, TOOL_FOTA_OEM_KEY_FNAME)

            if os.path.exists(oem_key):
                if (DEBUG): logD("Remove existing %s to create new one" % oem_key)
                common.rmdirs(oem_key)
            
            [__code, __msg] = self.prepareKey(__req, __req.enc_key_info, key_dir)
            if (DEBUG): logD("prepareKey enc_key_id ret %d - %s" % (__code, __msg))
        
        if (__code == common.ERR_NONE):
            __req.key_working_folder = key_dir
            switcher = {
                    "encrypt":self.encryptOrSign,
                    "sign":self.encryptOrSign,
                    }

            # select correspoinding sign method
            log("sign for type %s" % __req.type, TAG, True)
            func = switcher.get(__req.type)
            if func is None:
                func = lambda req: SignResp(__req, -1, "invalid 'type' option (%s), must by in %s" % (req.type, TYPE_LIST))

            return func(__req)
        else:
            logE("Invalid key", TAG)
            return SignResp(__req, common.ERR_FAILED, "invalid key")


    # Get template render for webpage used to manual sign
    def get_html_render_for_manual_sign(self, request):
        from server.key.key_mng import keyMgr
        from server.sign import signfactory as signfactory
        sign_key_list = keyMgr().get_all_keys(tool=FOTA_TOOL_NAME, keytool = SIGN_KEY_TOOL_NAME)
        enc_key_list = keyMgr().get_all_keys(tool=FOTA_TOOL_NAME, keytool = ENC_KEY_TOOL_NAME)

        return render_template(
            "sign/sign_fota.html"
            , login=is_login(request)
            , module="FOTA"
            , type_list=TYPE_LIST
            , project_list=getProjectList()
            , model_list=getModelList()
            , algo_list=ALGO_LIST
            , username=current_username()
            , sign_key_list=sign_key_list
            , enc_key_list=enc_key_list
            )

    def getKeyToolList(self):
        return [SIGN_KEY_TOOL_NAME, ENC_KEY_TOOL_NAME]