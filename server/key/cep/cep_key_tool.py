#!/usr/bin/env python
#
#  IMPORT KEY
#


from flask import Flask, render_template_string
from flask_restful import Api, Resource, reqparse
from flask import send_file
from flask import render_template
from flask import request, abort, jsonify, send_from_directory
from server.app import app
from server.app import DEBUG
import os
from server.applog import log
from server.applog import logE
from server.applog import logD
from server.app import get_resp
from server.app import getRootInputDir
from server.app import getRootToolDir
from server.database.key import KEY_DATA_TYPE_RAW
from server.database.key import KEY_SOURCE_IMPORT_API
from server.database.key import ALG_LIST
from server.key.key_mng import KEY_FOLDER_NAME
from server import key as key
import traceback
from server import common as common
from server.database.key_info import KeyInfo
from flask_login import login_required
from server.common import extract_form_request



from server.key.key_mng import keyMgr
from server.key.key_tool import KeyRequest
from server.key.key_tool import KeyTool
import json
import zipfile
from io import BytesIO
import shutil
from server.login.login import is_login

from server.storage.storage_mgr import storageMgr

import server.key.general.command_tool as command_tool
from server.key.general.command_tool import getCommand
from server.key.general.command_tool import getListCommand
from server.key.general.command_tool import COMMAND_TYPE_GEN_KEY
from server.key.general.command_tool import prepareCommandTool
from server.key.general.command_tool import getParam



TAG="cepkeytool"

CEP_TOOL_NAME = "cepkeytool"

CEP_PRIV_KEY_FNAME = "cep_priv.key"

REQUIRE_KEY = {
    CEP_PRIV_KEY_FNAME:"."
    }

REQUIRE_KEY_DESC = {
    CEP_PRIV_KEY_FNAME:"CEP private key: RSA 2048 key"
}
#
# Key certificate generation tool
#
class CepKeyTool(KeyTool):
    
    def getName(self):
        return CEP_TOOL_NAME

    # return dic with key is file name and values is relative path (not include file)
    def get_require_keys(self):
        return REQUIRE_KEY


    def get_require_keys_desc(self):
        return REQUIRE_KEY_DESC
    
    # TODO: implement generation action
    def get_html_render(self, request):
        from server.login.login import is_login, current_username
        from server.app import getProjectList
        from server.app import getModelList
        from server.sign.signtboxcep import TBOX_CEP_TOOL_NAME
        from server.sign.signtboxcep import TBOX_CEP_TOOL_DESC
        commands = getListCommand(COMMAND_TYPE_GEN_KEY)
        root_key_list = keyMgr().get_all_keys(tool=TBOX_CEP_TOOL_NAME, keytool=CEP_TOOL_NAME)
        return render_template(
            "key/key_gen_cep.html"
            , login=is_login(request)
            , username=current_username()
            # common for key
            , module="Generate CEP Key using openssl"
            , project_list=getProjectList()
            , model_list=getModelList()
            , modelany = common.ANY_INFO
            # specific
            , cmd_list = commands
            , keytool = CEP_TOOL_NAME
            , toolname = TBOX_CEP_TOOL_NAME
            , tooldesc = TBOX_CEP_TOOL_DESC
            , root_key_list = root_key_list
            , key_none = common.NONE_KEY_ID
        )
    
    def parse(self, request):
        if (DEBUG): logD("parse", TAG)
        key_req = CEPKeyRequest()
        [ret, msg] = key_req.parse(request)
        return [ret, key_req if ret == common.ERR_NONE else msg]
        

    def do_generate_key(self, key_req):
        if (DEBUG): logD("do_generate_key", TAG)
        #TODO
        ret = common.ERR_NONE
        msg = ""

        log("prepare tool", TAG)
        # prepare tool dir, unzip tool to this dir
        tool_working_folder = os.path.join(key_req.out_working_folder, "tool")
        common.mkdir(tool_working_folder)
        [ret, msg] = prepareCommandTool(key_req.command, tool_working_folder)
        if ret != common.ERR_NONE:
            logE("Prepare tool failed %s" % msg, TAG)
            return [ret, msg]

        script = os.path.join(tool_working_folder, key_req.command.script)
        if not os.path.exists(script):
            logE("%s not found" % script, TAG, True)
            return [common.ERR_NOT_FOUND, "script not found"]

        import subprocess
        subprocess.call(['chmod', '-R', '0755', tool_working_folder])

        # prepare parameters
        params = {}
        # workign dir
        params[command_tool.PARAM_WORK_DIR] = key_req.out_working_folder
        # output dir
        params[command_tool.PARAM_OUT_DIR] = key_req.keydir
        # output dir for public file
        params[command_tool.PARAM_PUB_OUT_DIR] = key_req.pubkeydir
        # key name
        params[command_tool.PARAM_IN_NAME] = key_req.key_info.name
        
        # build param string
        if (DEBUG): logD("param %s" % str(params), TAG)
        paramstr = getParam(key_req.command, params)

        if (DEBUG): logD("paramstr %s" % paramstr, TAG)
        # run script
        command = "%s %s %s" % (
            script,
            "-v" if DEBUG else "",
            paramstr
             )
        log("Signing script: %s" % script, TAG)
        if (DEBUG): logD("command: " + str(command), TAG)

        import copy
        new_env = copy.deepcopy(os.environ)
        # run script
        try:
            import subprocess
            child = subprocess.run(command, shell=True, env=new_env, timeout = COMMAND_TIMEOUT_SECOND if COMMAND_TIMEOUT_SECOND > 0 else None)
            rescmd = child.returncode

            # check result
            if (DEBUG): logD("command %s" % str(rescmd))
            if rescmd != 0 :
                logE("Signed failed with command %s, res %s" % (command, str(rescmd)), TAG, True)
                ret = common.ERR_FAILED
            
        except:
            traceback.print_exc()
            msg = "Exception"
            ret = common.ERR_EXCEPTION

        # save to db
        if ret == common.ERR_NONE:
            files = common.search_files(key_req.keydir)
            if files is not None and len(files) > 0:
                for file in files:
                    fname = os.path.basename(file)
                    [ret, fid] = storageMgr().writeFile(file, key_req.commandid, key_req.key_info.name)
                    key_req.key_info.addFid(fname, fid)

            pubfiles = common.search_files(key_req.pubkeydir)
            if pubfiles is not None and len(pubfiles) > 0:
                for pubfile in pubfiles:
                    fname = os.path.basename(pubfile)
                    [ret, fid] = storageMgr().writeFile(pubfile, key_req.commandid, key_req.key_info.name)
                    key_req.key_info.addFid(fname, fid, isPub=True)

            # import key
            if ret == common.ERR_NONE:
                [ret, msg] = keyMgr().import_key(key_req.key_info, key_req.access_token, key_req.out_working_folder)

        key_req.clean()
        return [ret, msg]


PARAM_COMMAND="command"

COMMAND_TIMEOUT_MIN = 1
COMMAND_TIMEOUT_SECOND = (COMMAND_TIMEOUT_MIN * 60)
#
# Request to CEP Key
#
class CEPKeyRequest(KeyRequest):

    command =  None
    keydir =  ""
    pubkeydir =  ""
    commandid =  ""
    def __init__(self):
        super(CEPKeyRequest, self).__init__()
        self.command = None
        self.project = None
        self.model = None
        self.keydir = ""
        self.pubkeydir = ""
        self.commandid = ""
        
    # parse request
    def parse(self, request):
        if (DEBUG): logD("CEPKeyRequest parse", TAG)
        ret = common.ERR_FAILED
        msg = ""
        [ret, msg] = super(CEPKeyRequest, self).parse(request)

        if ret != common.ERR_NONE:
            logE("GenKeyRequest super failed %d - %s" % (ret, msg), TAG)
            return [ret, msg]

        self.commandid = common.extract_form_request(request, PARAM_COMMAND, is_int=False, default_data="")
        if (DEBUG): logD("commandid %s" % self.commandid, TAG)
        
        if self.commandid is not None and len(self.commandid) > 0:
            self.command = getCommand(self.commandid, COMMAND_TYPE_GEN_KEY)

        if self.command is None:
            return [common.ERR_NOT_FOUND, "command not found"]
        
        if (DEBUG): logD("command %s" % self.command, TAG)

        # check target key tool
        if self.key_info.target_keytool is None:
            if (DEBUG): logD("not key tool, set default to %s" % CEP_TOOL_NAME, TAG)
            self.key_info.target_keytool = str([CEP_TOOL_NAME]) 

        # key dir
        self.keydir = os.path.join(self.out_working_folder, "keydir")
        common.mkdir(self.keydir)
        self.pubkeydir = os.path.join(self.out_working_folder, "pubkeydir")
        common.mkdir(self.pubkeydir)
        
        if ret == common.ERR_NONE:
            [ret, msg] = self.validate()
            
        if (DEBUG): logD("parse %d - %s" % (ret, msg), TAG)
        
        return [ret, msg]

    
    def toString(self, isFull=False):
        str = ""
        str += "command: " % self.command.toString() if self.command is not None else ""
        str += "\n"
        return str

   # check request info
    def validate(self):
        __result_str = ""
        [__result_code, __result_str] = super(CEPKeyRequest, self).validate()

        if self.command is None:
            __result_code = common.ERR_INVALID_ARGS
            __result_str += "No command, "
        
        return [__result_code, __result_str]