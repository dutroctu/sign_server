#!/usr/bin/env python
#
#  IMPORT KEY
#


from flask import Flask
from flask_restful import Api, Resource, reqparse
from flask import send_file
from flask import render_template
from flask import request, abort, jsonify, send_from_directory
from server.app import app
import os
from server.applog import log
from server.applog import logE
from server.applog import logD
from server.app import get_resp
from server.app import DEBUG
from server.app import getRootInputDir
from server.database.key import KEY_DATA_TYPE_RAW
from server.database.key import KEY_DATA_TYPE_FILE
from server.database.key import KEY_SOURCE_IMPORT_API
from server.database.key import ALG_LIST
from server.key.key_mng import KEY_FOLDER_NAME
from server.key.key_mng import keyMgr
from server import key as key
import traceback
import shutil
from server import common as common
from server.database.key_info import KeyInfo
from flask_login import login_required
from server.common import extract_form_request
from server.key.key_tool import KeyRequest
from server.key.key_tool import KeyTool
import zipfile

TAG="importkey"

IMPORT_KEY_TOOL_NAME = "importkey"

# Key import request
class ImportKeyRequest(KeyRequest):

    key_working_folder = None
    def __init__(self):
        super(ImportKeyRequest, self).__init__()
        self.key_working_folder = None
    
    def parse(self, request):
        if (DEBUG): logD("parse", TAG)
        [ret, msg] = super(ImportKeyRequest, self).parse(request)
        if ret != common.ERR_NONE:
            log("Parent return error %d" % ret)
            return [ret, msg]

        self.key_info.pwd = extract_form_request(request, common.PARAM_PASSWORD)
        if self.key_info.pwd is not None:
            self.key_info.pwd = self.key_info.pwd.strip()
        
        if (DEBUG): logD("key_info: %s" % self.key_info.toString(), TAG)

        self.key_working_folder = os.path.join(self.in_working_folder, "keydir")
        common.mkdir(self.key_working_folder)

        return [common.ERR_NONE, "OK"]


#
# Generic import key tool
#
class ImportKeyTool(KeyTool):
    
    def getName(self):
        return IMPORT_KEY_TOOL_NAME

        # Get template render for webpage used to manual sign
    def get_html_render(self, request):
        from server.sign import signfactory as signfactory
        from server.login.login import is_login, current_username
        from server.app import getProjectList
        from server.app import getModelList
        from server.sign.signfactory import SignFactory
        from server.sign.signfactory import RENESAS_TOOL_NAME
        from server.sign.signfactory import RENESAS_TOOL_DESC
        from server.key.key_mng import get_keytool_list
        from server.database.account import ACCOUNT_TYPE_ADMIN
        from server.database.account import ACCOUNT_TYPE_MOD
        from server.database.account import ACCOUNT_TYPE_USER

        key_list = keyMgr().get_all_keys(tool=RENESAS_TOOL_NAME)
        login=is_login(request, 
            account_types=[ACCOUNT_TYPE_ADMIN, ACCOUNT_TYPE_MOD, ACCOUNT_TYPE_USER]
        )
        return render_template(
                "key/import_key.html"
                , login=login
                , model_list=getModelList()
                , project_list=getProjectList()
                , tool_list=SignFactory.get_sign_tool_list()
                , username=current_username()
                , keytool_list=get_keytool_list()
                , modelany = common.ANY_INFO
                )

    def parse(self, request):
        key_req = ImportKeyRequest()
        [ret, msg] = key_req.parse(request)
        if ret == common.ERR_NONE:
            key_req.key_info.data_type = KEY_DATA_TYPE_FILE
            return [ret, key_req]
        else:
            return [ret, msg]

    # prepare to import, unzip key?
    def prepare_import_key(self, key_req, input_key_dir=None):
        if (DEBUG): logD("prepare_import_key", TAG)
        try:
            if 'files' in key_req.upload_files:
                files = key_req.upload_files['files']
                if files is not None and len(files) > 0:
                    for file in files:
                        if (DEBUG): logD("keyfile: %s" % file, TAG)
                        log("prepare import key, extract/copy file")
                        if common.isZipFile(file):
                            if (DEBUG): logD("extract tool from %s to %s" %(file, key_req.key_working_folder), TAG)
                            with zipfile.ZipFile(file, 'r') as zip_ref:
                                zip_ref.extractall(key_req.key_working_folder)
                        else:
                            shutil.copy(file, key_req.key_working_folder)
                    ret = [common.ERR_NONE, "OK"]
                else:
                    ret = [common.ERR_NO_DATA, "no data"]
            else:
                ret = [common.ERR_NO_DATA, "no data"]
        except:
            traceback.print_exc()
            ret = [common.ERR_EXCEPTION, "Failed to save key files, exception"]
        
        return ret
    

    # do import key
    def do_import_key(self, key_req, key_dir):
        if (DEBUG): logD("do_import_key", TAG)
        from server.sign.signfactory import SignFactory
        ret = common.ERR_NONE
        msg = ""

        keytoolnames = key_req.key_info.getKeyTools()
        if (keytoolnames is None or len(keytoolnames) == 0):
            return [common.ERR_INVALID_ARGS, "no selected key tool"]
        
        signtoolnames = key_req.key_info.getTools()
        if (signtoolnames is None or len(signtoolnames) == 0):
            return [common.ERR_INVALID_ARGS, "no selected sign tool"]
        
        signtools = SignFactory.get_sign_tool_list()
        from server.sign.signfactory import SignFactory

        #validate key tool first
        if (DEBUG): logD("validate key with sign tool, sign tool may call key_tool to validate", TAG)
        for toolname in signtoolnames:
            if (DEBUG): logD("toolname %s" % toolname, TAG)
            signtool = SignFactory.get_sign_tool_by_name(toolname)
            if signtool is not None:
                for keytoolname in keytoolnames:
                    if (DEBUG): logD("keytoolname %s" % keytoolname, TAG)
                    keypass = key_req.key_info.pwd if (key_req.key_info.pwd is not None and len(key_req.key_info.pwd) > 0) else None
                    [ret, msg] = signtool.validate_key(key_req=key_req, keypass=keypass, key_dir=key_req.key_working_folder, keytoolname=keytoolname)
                    if ret != common.ERR_NONE:
                        break
            else:
                ret = common.ERR_NOT_FOUND
                msg = "not found sign tool %s" % toolname

            if ret != common.ERR_NONE:
                break
        
        if (DEBUG): logD("validate key result %d - %s" % (ret, msg), TAG)

        if ret == common.ERR_NONE:
            if (DEBUG): logD("Call each key tool to do import")
            # call for each key tool to do import key
            from server.key.key_mng import get_keytool_from_name
            for keytoolname in keytoolnames:
                if (DEBUG): logD("import key for key tool %s" % keytoolname)
                keytool = get_keytool_from_name(keytoolname)
                if keytool is not None:
                    [ret, msg] = keytool.prepare_import_key(key_req, key_req.key_working_folder)
                    
                    if ret == common.ERR_NONE:
                        [ret, msg] = keytool.do_import_key(key_req, key_req.key_working_folder)
                    
                    ret = keytool.finalize_import_key(ret, key_req)

                    if ret != common.ERR_NONE:
                        break
                
        if (DEBUG): logD("import key done, ret %d" % ret)
        return [ret, msg]


    # get help for tool
    def get_help(self, req, keytoolname):
        from server.key.key_mng import get_keytool_from_name
        if (DEBUG): logD("get_help %s" % keytoolname, TAG)
        tool = get_keytool_from_name(keytoolname)
        if tool is not None:
            return tool.get_help(req, keytoolname)
        else:
            return None