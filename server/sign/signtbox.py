#!/usr/bin/env python
#
#  SIGN FOT TBOX
#
from flask import Flask
from flask_restful import Api, Resource, reqparse
from flask import send_file
from flask import render_template
from flask import request, abort, jsonify, send_from_directory
from server.app import app
from server.app import ROOT_DIR
from server.app import KEEP_OUTPUT_FILE
from server import common as common
import os
from server.applog import log
from server.applog import logD
from server.applog import logE
from datetime import datetime

from server.sign.signreq import SignRequest
from server.sign.signreq import SignTool
from server.sign import signfactory as signfactory

from server.app import getProjectList
from server.app import getModelList
from server.common import DEFAULT_KEY_ID
from server.common import INVALID_KEY_ID
import zipfile
from io import BytesIO
import shutil
import subprocess
from server.login.login import is_login, current_username
import traceback
import sys

from server.sign.signresp import SignResp
from server import database as database
# from server.key.key_mng import keyMgr
from server.storage import storageMgr

from server.key.quectel.sb_attest_key_tool import KEY_TOOL_NAME as ATTEST_KEY_TOOL_NAME
from server.key.quectel.sb_dm_key_tool import KEY_TOOL_NAME as DM_KEY_TOOL_NAME
from server.key.quectel.root_key_tool import KEY_TOOL_NAME as ROOT_KEY_TOOL_NAME
from server.app import DEBUG
TAG="SignTBox"
TBOX_TOOL_NAME = "tbox"
TBOX_TOOL_DESC = "Sign TBox firmware"

# toolg for signing
TOOL_TBOX_SECTOOL_ZIP = os.path.join(ROOT_DIR, "tool/tbox/sectool.zip")

# Sign script name
TOOL_SCRIPT = "sign.sh"

TYPE_LIST = [
    "auto", # try to guess
    "secure",  # secure boot key
    "verity",  # verity key
    "bulk" # multi files
    ]

SIGN_ID_LIST = [
    "auto", 
    "sbl1", 
    "NPRG", 
    "ENPRG",
    "prog_nand_firehose",
    "tz",
    "devcfg",
    "cmnlib",
    "haventkn",
    "smplap32",
    "qlaesutl",
    "qlrsautl",
    "qlfuseutl",
    "appsboot",
    "rpm",
    "mba",
    "modem",
    "mcfg_hw",
    "mcfg_sw",
    "rootfs",
    "oemapp",
    "legato",
    "bootimg",
    ]

PLATFORM_LIST = [
    "9607"
    ]
    

INPUT_IMAGE_TAG = "image"


OEM_ROOTCA_CERT_FNAME = "oem_rootca.cer"
OEM_ATTEST_CERT_FNAME = "oem_attestationca.cer"
OEM_ATTEST_KEY_FNAME = "oem_attestationca.key"

DM_OEM_ROOTCA_CERT_FNAME = "oem_rootca.cer"
DM_OEM_ATTEST_CERT_FNAME = "oem_attestationca.cer"
DM_OEM_ATTEST_KEY_FNAME = "oem_attestationca.key"

# Sign Request of Tbox
class SignRequestTbox(SignRequest):
    sign_id = "" # sign id need to be passed to signing tool (i.e. tz, boot, ...)
    platform = "" # platform chipset like 9607
    type = "" # type of signing like secure/verify/bulk

    attest_key_id = None
    attest_key_info = None
    
    dm_key_id = None
    dm_key_info = None
    
    key_working_folder = None
    def __init__(self, __request):
        super(SignRequestTbox, self).__init__(__request, TBOX_TOOL_NAME)

        self.sign_id = request.form.get('sign_id')
        self.platform = request.form.get('platform')
        self.type = request.form.get('type')
       
        [self.attest_key_id, self.attest_key_info] = self.getKeyInfo(request, "attest_key_id", "attest_key_name", ATTEST_KEY_TOOL_NAME)
        [self.dm_key_id, self.dm_key_info] = self.getKeyInfo(request, "dm_key_id", "dm_key_name", DM_KEY_TOOL_NAME)

    def toString(self):
        str = super(SignRequestTbox, self).toString()
        if (self.sign_id is not None):
            str += "sign_id: %s, " % self.sign_id
        if (self.platform is not None):
            str += "platform: %s, " % self.platform
        if (self.type is not None):
            str += "type: %s, " % self.type
        str += "\n"
        return str

    # return dic of keyinfo, with key is keytype, value is key_info
    def getListKeyInfo(self):
        return {
            "attest_key_info":self.attest_key_info,
            "dm_key_info":self.dm_key_info
            }

# TBox signing tool
class SignTbox(SignTool):

    def getName(self, desc=False):
        return TBOX_TOOL_NAME if not desc else TBOX_TOOL_DESC

    # parse request
    def parse_request(self, request):
        return SignRequestTbox(request)

    # checi request
    def check(self, __req):
        [__code, __msg] = super(SignTbox, self).check(__req)
        if (__code != 0):
            return [__code, __msg]

        __result_str = ""
        __result_code = 0

        # check sign id param
        # if __req.sign_id is None or len(__req.sign_id) == 0:
        #     __result_code = -1
        #     __result_str += "No sign_id, "
        # else:
        #     if __req.sign_id not in SIGN_ID_LIST:
        #         __result_code = -1
        #         __result_str += "invalid sign id %s, " % __req.sign_id

        # check platform param
        if __req.platform is None or len(__req.platform) == 0:
            __result_code = -1
            __result_str += "No platform, "
        else:
            if __req.platform not in PLATFORM_LIST:
                __result_code = -1
                __result_str += "invalid platform %s, " % __req.platform

        # check type param
        if __req.type is None or len(__req.type) == 0:
            __result_code = -1
            __result_str += "No type, "
        else:
            if __req.type not in TYPE_LIST:
                __result_code = -1
                __result_str += "invalid type %s, " % __req.type

        if __result_code == 0 and __req.attest_key_id is None:
            __result_code = -1
            __result_str += "No attest_key_id/name"

        if __result_code == 0 and __req.dm_key_id is None:
            __result_code = -1
            __result_str += "No dm_key_id/name"

        if __result_code == 0 and __req.attest_key_id == INVALID_KEY_ID:
            __result_code = -1
            __result_str += "invalid/not exist attest_key_id/name"

        if __result_code == 0 and __req.dm_key_id == INVALID_KEY_ID:
            __result_code = -1
            __result_str += "invalid/not exist dm_key_id/name"

            
        if (__result_code == 0):
            __result_str = "OK"

        return [__result_code, __result_str]

    def sign_tbox(self, __req):

        if (INPUT_IMAGE_TAG not in __req.file_path_list or len(__req.file_path_list[INPUT_IMAGE_TAG]) == 0):
            return SignResp(__req, -1, "Uploaded file required input type name is '%s'" % INPUT_IMAGE_TAG)
        in_file = __req.file_path_list[INPUT_IMAGE_TAG][0] # TODO: FIXME: support multi files
        fname = __req.getFileName(INPUT_IMAGE_TAG)
        sign_fname = __req.getSignFile(INPUT_IMAGE_TAG)

        if (in_file is None) or not os.path.exists(in_file):
            return SignResp(__req, -1, "file not found")

        output_file = os.path.join(__req.out_working_folder, sign_fname)

        # bulk result have 2 results: full and final signed files.
        # depend on purpose, caller can user any of them
        signed_image_fname = "%s_signed" % fname
        signed_image_fname_zip = "%s.zip" % signed_image_fname
        signed_image_folder = os.path.join(__req.out_working_folder, signed_image_fname) # signed file is put in "output" folder
        signed_image_folder_zip = os.path.join(__req.out_working_folder, signed_image_fname_zip)

        __sign_id = __req.sign_id
                # if sign id is auto, try to guest basing on file name
        if __sign_id == "auto":
            __tmp = os.path.splitext(fname)
            __sign_id = __tmp[0]
            # if (__sign_id not in SIGN_ID_LIST):
            #     return SignResp(__req, -1, "not found suitable sign id base on file name")

        # check if tool folder is ready
        # f*ck qualcomm, input and tool must be in same location
        __script = os.path.join(__req.tool_working_folder, TOOL_SCRIPT)

        if not os.path.exists(__script):
            logE("%s not found" % __script, TAG, True)
            return SignResp(__req, -1, "Not found script to sign")
        filetype = "file"
        keytype = "secure"
        if __req.type == "bulk":
            filetype = "bulk"
            keytype=""
        elif __req.type == "auto":
            if (in_file.endswith(".zip")): # zip file, it's bulk
               filetype = "bulk"
               keytype=""
            else:
                filetype = "file" # not zip file, it's standalone file
                keytype=""
        else: # secure or verity
            filetype = "file"
            keytype=__req.type # already check in allow range before, not need to check again
        # build command to start signing
        command = "%s --input=%s --output=%s --keytype=%s --filetype=%s --signid=%s" % (
            __script, in_file, signed_image_folder, keytype,filetype,__sign_id)
      
        log ("command: " + command, TAG, True)
        # start signing
        __res = os.system(command)
        if (DEBUG): logD("command %d" % __res)
        if __res != 0 :
            logE("Signed failed with command %s, res %d" % (command, __res), TAG, True)
            return SignResp(__req, -1, "Signed failed %d" % __res)

        # check result
        log("sign output file %s" % signed_image_folder, TAG, True) # output_file is full signed binaries, to be used by caller for next signing steps
        if not os.path.exists(signed_image_folder):
            logE("output %s not found" % signed_image_folder, TAG, True)
            return SignResp(__req, -1, "Not found output")
        else:
            ret = common.zipfolder(signed_image_folder, signed_image_folder_zip)
            if (not ret) or not os.path.exists(signed_image_folder_zip):
                return SignResp(__req, -1, "Failed to zip data")

        resp = SignResp(__req, 0, "OK")
        
        if resp.copy_to_download(signed_image_fname_zip, signed_image_folder_zip):

            # well done, setup data to be response to caller
            __req.session.set_data(resp) # assume that session is already checked before this function
        else:
            resp.set_response_msg(-1, "Failed to generate download file")

        return resp
    
    # do signing
    def do_sign(self, __req):
        # check paramater
        [__code, __msg] = self.check(__req)

        if (__code != 0):
            return SignResp(__req, __code, __msg)

        # extract tool to output folder
        [__code, __msg] = self.prepareTool(__req, TOOL_TBOX_SECTOOL_ZIP)

        if (__code != common.ERR_NONE):
            return SignResp(__req, __code, __msg)

        # Get key basing on key id, or use default one
        log ("Sign with attest key: %s" % __req.attest_key_id, TAG, True)
        log ("Sign with dm key: %s" % __req.dm_key_id, TAG, True)
        
        # attestion key
        attest_dir = os.path.join(__req.tool_working_folder, "cert")
        # DM verity key
        dm_dir = os.path.join(attest_dir, "dm")
        
        if (__req.attest_key_info != None):
            if os.path.exists(attest_dir):
                if (DEBUG): logD("Remove existing in %s to create new one" % attest_dir, TAG)
                common.rm_file_in_dir(attest_dir)
            else:
                common.mkdir(attest_dir)
            [__code, __msg] = self.prepareKey(__req, __req.attest_key_info, attest_dir)
           
        if  (__code == common.ERR_NONE) and __req.dm_key_info != None:
            if os.path.exists(dm_dir):
                if (DEBUG): logD("Remove existing in %s to create new one" % dm_dir, TAG)
                common.rm_file_in_dir(dm_dir)
            else:
                common.mkdir(dm_dir)
            [__code, __msg] = self.prepareKey(__req, __req.dm_key_info, dm_dir)


        if __code == common.ERR_NONE:
            resp = self.sign_tbox(__req)
            if (not KEEP_OUTPUT_FILE):
                common.rmdirs(__req.out_working_folder)
            return resp
        else:
            if not KEEP_OUTPUT_FILE:
                common.rmdirs(__req.out_working_folder)
            return SignResp(__req, __code, __msg)


    # Get template render for webpage used to manual sign
    def get_html_render_for_manual_sign(self, request):
        from server.key.key_mng import keyMgr
        from server.sign import signfactory as signfactory
        sb_key_list = keyMgr().get_all_keys(tool=TBOX_TOOL_NAME, keytool = ATTEST_KEY_TOOL_NAME)
        dm_key_list = keyMgr().get_all_keys(tool=TBOX_TOOL_NAME, keytool = DM_KEY_TOOL_NAME)
        
        return render_template(
            "sign/sign_tbox.html"
            , login=is_login(request)
            , module="TBOX"
            , type_list=TYPE_LIST
            , project_list=getProjectList()
            , platform_list=PLATFORM_LIST
            , sign_id_list=SIGN_ID_LIST
            , model_list=getModelList()
            , default_key_id=DEFAULT_KEY_ID
            , sb_key_list=sb_key_list
            , dm_key_list=dm_key_list
            , username=current_username()
            , toolname=TBOX_TOOL_NAME
            , attestkeytoolname=ATTEST_KEY_TOOL_NAME
            , dmkeytoolname=DM_KEY_TOOL_NAME
            )
    def getKeyToolList(self):
        return [ATTEST_KEY_TOOL_NAME, DM_KEY_TOOL_NAME, ROOT_KEY_TOOL_NAME]