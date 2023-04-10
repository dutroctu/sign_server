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
from server.app import DEBUG

import os
from server import applog as applog 
from server.applog import log
from server.applog import logD
from server.applog import logE
from server.applog import printBytes
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

# from server.key.key_mng import keyMgr
from server.storage import storageMgr
from server.key.general.gen_key_tool import GENKEY_TOOL_NAME

import server.key.general.command_tool as command_tool
from server.key.general.command_tool import getCommand
from server.key.general.command_tool import getListCommand
from server.key.general.command_tool import COMMAND_TYPE_GEN_KEY
from server.key.general.command_tool import COMMAND_TYPE_GEN_DATA
from server.key.general.command_tool import prepareCommandTool
from server.key.general.command_tool import getParam

from server.common import INVALID_KEY_ID

TAG = "commontool"
COMMON_TOOL_NAME = "commontool"
COMMON_TOOL_DESC = "Common sign/encrypt tool"

# command timeout, to avoid locking server (i.e. key need password, but no password is set)
# COMMAND_TIMEOUT_SECOND=300
COMMAND_TIMEOUT_MIN=30
COMMAND_TIMEOUT_SECOND=(COMMAND_TIMEOUT_MIN*60)

PARAM_COMMAND="command"
PARAM_DATA="data"
PARAM_DATA2SIGN="data2sign"
PARAM_DATA2SIGN64="data2sign64"

class SignRequestCommon(SignRequest):
    key_id = None
    key_info = None

    key_working_folder = None

    command =  None
    commandid =  ""
    data =  ""
    data2sign =  ""
    target_tool = None
    keytool = None
    def __init__(self, request):
        super(SignRequestCommon, self).__init__(request, COMMON_TOOL_NAME)
        if (DEBUG): logD("request %s" % str(request.form), TAG)


        self.target_tool = common.extract_form_request(request, common.PARAM_TOOL, default_data=None)
        self.keytool = common.extract_form_request(request, common.PARAM_KEYTOOL, default_data=None)

        if (DEBUG): logD("tool %s" % self.target_tool, TAG)
        if (DEBUG): logD("keytool %s" % self.keytool, TAG)

        if self.target_tool is None:
            log("No target_tool info", TAG)

        if self.keytool is None:
            logE("No keytool info", TAG)

        [self.key_id, self.key_info] = self.getKeyInfo(request, "key_id", "key_name", keytool=self.keytool, tool=self.target_tool)

        if self.key_info is None:
            logE("No key_info info", TAG)

        self.commandid = common.extract_form_request(request, PARAM_COMMAND, is_int=False, default_data="")
        self.data = common.extract_form_request(request, PARAM_DATA, is_int=False, default_data="")

        if (DEBUG): logD("commandid %s" % self.commandid, TAG)
        if (DEBUG): logD("data %s" % self.data, TAG)

        if self.commandid is not None and len(self.commandid) > 0:
            self.command = getCommand(self.commandid, COMMAND_TYPE_GEN_DATA)

        self.data2sign = common.extract_form_request(request, PARAM_DATA2SIGN, is_int=False, default_data="")
        if self.data2sign is None or len(self.data2sign) == 0:
            data2sign64 = common.extract_form_request(request, PARAM_DATA2SIGN64, is_int=False, default_data="")
            if (data2sign64 is not None and len(data2sign64) > 0):
                data2sign64 = data2sign64.replace(" ", "+") # for the case that flask replace + by space (URL encode/decode)

                if (DEBUG): logD("decode data2sign64 %s" % data2sign64, TAG)

                self.data2sign = common.decodeBase64(data2sign64)
                printBytes("raw data", self.data2sign, TAG)

        self.key_working_folder = None
       
    def toString(self):
        str = super(SignRequestCommon, self).toString()
        str += "key_id: %s, " % self.key_id
        
        str += "\n"
        return str
    
    # return dic of keyinfo, with key is keytype, value is key_info
    def getListKeyInfo(self):
        return {
            "key_info":self.key_info,
            }

    def getSignInfo(self):
        return {
            "target_tool":self.target_tool,
            "keytool":self.keytool,
            "commandid":self.commandid
            }

class SignCommon(SignTool):

    def getName(self, desc=False):
        return COMMON_TOOL_NAME if not desc else COMMON_TOOL_DESC

    def parse_request(self, request):
        if (DEBUG): logD("SignCommon parse_request")
        return SignRequestCommon(request)

    def check(self, __req):
        [__code, __msg] = super(SignCommon, self).check(__req)

        if (__code != 0):
            return [__code, __msg]

        __result_str = ""
        __result_code = 0


        if __req.command is None:
            __result_code = -1
            __result_str += "Command %s not found" % __req.commandid

        if __result_code == 0 and __req.key_info is None:
            __result_code = -1
            __result_str += "No key_id or key_name"

        
        if (__result_code == 0):
            __result_str = "OK"

        return [__result_code, __result_str]

    # Sign target file
    def sign_target(self, __req):

        # prepare script to run
        script = os.path.join(__req.tool_working_folder, __req.command.script)
        if (DEBUG): logD("sign_script %s" % script)
        if not os.path.exists(script):
            logE("%s not found" % script, TAG, True)
            return SignResp(__req, -1, "Not found script to sign")

        signed_image_folder = os.path.join(__req.out_working_folder, "signed") # signed file is put in "output" folder
        common.mkdir(signed_image_folder)

        # prepare files to be signed/encrypt/...

        img_dir = os.path.join(__req.tool_working_folder, "input") # signed file is put in "output" folder
        common.mkdir(img_dir)

        no_file = 0
        output_resp = False
        for tag,files in __req.file_path_list.items():
            for file in files:
                if file is not None and len(file) > 0 and os.path.exists(file):
                    # TODO: may be duplicate file name, fix me please
                    if common.isZipFile(file):
                        if (DEBUG): logD("extract zip from %s to %s" %(file, img_dir), TAG)
                        with zipfile.ZipFile(file, 'r') as zip_ref:
                            zip_ref.extractall(img_dir)
                        no_file += 1
                    else:
                        shutil.copy(file, img_dir)
                        no_file += 1
        if (DEBUG): logD("Found %d file" % no_file, TAG)
        data2sign_fpath = None
        if no_file == 0:
            if __req.data2sign is not None and len(__req.data2sign) > 0:
                data2sign_fpath = os.path.join(img_dir, "data2sign")
                if (DEBUG): logD("Write %s file %s" % (__req.data2sign, data2sign_fpath), TAG)
                write_ret = True
                if isinstance(__req.data2sign, str):
                    write_ret = common.write_string_to_file(data2sign_fpath, __req.data2sign)
                else:
                    write_ret = common.write_to_file(data2sign_fpath, __req.data2sign)
                if write_ret:
                    __req.output_resp = not __req.zip_output
                else:
                    logE("faile to write data to sign to file", TAG, True)
                    return SignResp(__req, -1, "prepare data to sign failed")
            else:
                logE("not found any file/data to sign", TAG, True)
                return SignResp(__req, -1, "not found any file/data to sign")

        # prepare paramaters string for commands
        params = {}
        password=None
        import copy
        new_env = copy.deepcopy(os.environ)
        # check if key has password, input password to environment
        if __req.key_info is not None and __req.key_info.pwd is not None and len(__req.key_info.pwd) > 0:
            if (DEBUG): logD("Set password for key %s" % (__req.key_info.id), TAG)
            new_env[command_tool.PARAM_PASS_ENV] = __req.key_info.pwd
            params[command_tool.PARAM_PASS_ENV] = command_tool.PARAM_PASS_ENV

        params[command_tool.PARAM_KEY_DIR] = __req.key_working_folder
        params[command_tool.PARAM_WORK_DIR] = __req.tool_working_folder
        params[command_tool.PARAM_OUT_DIR] = signed_image_folder
        params[command_tool.PARAM_IN_TEXT] = __req.data
        params[command_tool.PARAM_IN_DIR] = img_dir
        paramstr = getParam(__req.command, params)

        # run script
        command = "%s %s %s" % (
            script,
            "-v" if DEBUG else "",
            paramstr if paramstr is not None else ""
             )

        log("Signing script: %s" % script, TAG)
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
        
        if __req.output_resp:
            jdata = {}
            # jdataout = {}
            import json
            # jdata["data2sign"] = common.encodeBase64(bytes(__req.data2sign, 'utf-8'))
            if data2sign_fpath is not None:
                shutil.copy(data2sign_fpath, params[command_tool.PARAM_OUT_DIR])
            # jdata["output"] = jdataout
            for fname in os.listdir(params[command_tool.PARAM_OUT_DIR]):
                if not fname.endswith(".log"):
                    jdata[fname] = common.read_from_file_to_base64(os.path.join(params[command_tool.PARAM_OUT_DIR], fname))
            jstring = json.dumps(jdata)
            if (DEBUG): logD("jstring %s" % jstring)
            resp = SignResp(__req, common.ERR_NONE, jstring)
             
        else:
            # pack output
            resp = self.packOutput(__req, signed_image_folder)

        return resp

    # do signing
    def do_sign(self, __req):
        if (DEBUG): logD("do sign")
        # check/prepare tool
        # prepare tool dir, unzip tool to this dir
        __req.tool_working_folder = os.path.join(__req.out_working_folder, "tool")
        common.mkdir(__req.tool_working_folder)
        [ret, msg] = prepareCommandTool(__req.command, __req.tool_working_folder)
        if ret != common.ERR_NONE:
            logE("Prepare tool failed %s" % msg, TAG)
            return [ret, msg]

        if (ret != common.ERR_NONE):
            return SignResp(__req, ret, msg)

        import subprocess
        subprocess.call(['chmod', '-R', '0755', __req.tool_working_folder])

        # Get key basing on key id, or use default one
        log ("Sign with key: %s" % __req.key_id, TAG, True)
        
        # prepare key
        key_dir = os.path.join(__req.out_working_folder, "key")
        
        if __req.key_info != None:
            if os.path.exists(key_dir):
                if (DEBUG): logD("Remove existing key_dir to create new one")
                common.rm_file_in_dir(key_dir)
            else:
                common.mkdir(key_dir)
            if (DEBUG): logD("Prepare key", TAG)
            [ret, __msg] = self.prepareKey(__req, __req.key_info, key_dir)
            if (ret == common.ERR_NONE):
                __req.key_working_folder = key_dir
            else:
                logE("Prepare key failed", TAG)
        else: # if not key is set, return error
            ret = common.ERR_FAILED
            __msg = "No key"
            logE("no key", TAG)
        
        if (DEBUG): logD("key_working_folder %s" % __req.key_working_folder, TAG)
        if (ret != common.ERR_NONE):
            applog.logE("Prepare key failed %d" % ret)
            return SignResp(__req, ret, __msg)
       
        return self.sign_target(__req)


    # Get template render for webpage used to manual sign
    def get_html_render_for_manual_sign(self, request):
        from server.sign import signfactory as signfactory
        from server.key.general.command_tool import COMMAND_TYPE_GEN_DATA
        from server.key.key_mng import get_keytool_list
        commmands = getListCommand(COMMAND_TYPE_GEN_DATA)
        return render_template(
            "sign/sign_common.html"
            # common for headers
            , login=is_login(request)
            , username=current_username()
            # common for sign
            , module="Common sign/encrypt/decrypt/generate cert"
            , project_list=getProjectList()
            , model_list=getModelList()
            # specific
            , default_key_id=common.DEFAULT_KEY_ID
            , keytool_list=get_keytool_list()
            # , key_list=key_list
            , toolname=COMMON_TOOL_NAME
            , keytoolname=GENKEY_TOOL_NAME
            , cmd_list = commmands
            )

    def getKeyToolList(self):
        return [GENKEY_TOOL_NAME]