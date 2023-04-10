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
from server.app import DEBUG

TAG="androidavb"

KEYINFO="keyinfo"
REQUIRE_KEY = {
    KEYINFO:".", 
    # "vbmeta.pem":".",
}
KEY_TOOL_NAME = "androidavb"

REQUIRE_KEY_DESC = {
    KEYINFO:"AVB key info",
}
class AndroidAvbKeyTool(KeyTool):

    def getName(self):
        return KEY_TOOL_NAME

    # return dic with key is file name and values is relative path (not include file)
    def get_require_keys(self):
        return REQUIRE_KEY

    def validate_key(self, key_req = None, keypass = None, input_key_dir = None):
        if (DEBUG): logD("validate_key", TAG)
        if (DEBUG): logD("input_key_dir %s " % input_key_dir, TAG)
        require_keys = self.get_require_keys()
        if (DEBUG): logD("require_keys %s " % str(require_keys), TAG)
        if require_keys is None:
            return [common.ERR_NOT_SUPPORT, "not support"]
        
        if input_key_dir is None or not os.path.exists(input_key_dir):
            return [common.ERR_NOT_FOUND, "no key dir, or key dir not exist"]
        
        for key,root in require_keys.items():
            if not os.path.exists(os.path.join(input_key_dir, root, key)):
                logE("Validate key failed, not found %s" % key, TAG)
                return [common.ERR_NOT_FOUND, "Not found %s" % key]

        keyinfo = os.path.join(input_key_dir, KEYINFO)
        msg = ""
        ret = common.ERR_NONE
        if os.path.exists(keyinfo):
            try:
                lines = None
                with open(keyinfo) as f:
                    lines = f.readlines()
                
                if lines is not None and len(lines) > 0:
                    for line in lines:
                        line = line.strip()
                        if (DEBUG): logD("line %s" % line, TAG)
                        if line is not None and len(line) > 0:
                            split=line.strip().split(":", 1)
                            if split is not None and len(split) > 1:
                                partition = split[0].strip()
                                keys = split[1].strip().split(",", 1)
                                if keys is not None and len(keys) > 1:
                                    file = keys[0].strip()
                                    alg = keys[1].strip()
                                    if alg is None or len(alg) == 0:
                                        ret = common.ERR_INVALID_ARGS
                                        msg = "invalid arg %s" % line
                                        break
                                    if file is not None and len(file) > 0:
                                        fpath = os.path.join(input_key_dir, file)
                                        if not os.path.exists(fpath):
                                            ret = common.ERR_NOT_FOUND
                                            msg = "%s not found" % file
                                            break
                                    else:
                                        if (DEBUG): logD("Found file %s" % file, TAG)
                                else:
                                    ret = common.ERR_INVALID_ARGS
                                    msg = "invalid file info %s" % line
                                    break
                            else:
                                ret = common.ERR_INVALID_ARGS
                                msg = "invalid key info %s" % line
                                break
            except:
                traceback.print_exc()
                ret = common.ERR_EXCEPTION
                msg = "exception"
        else:
            ret = common.ERR_NOT_FOUND
            msg = "not found keyinfo"
        
        if (DEBUG): logD("ret %d msg %s" % (ret, msg), TAG)
        return [ret, msg]



    def get_require_keys_desc(self):
        return REQUIRE_KEY_DESC
        

    # TODO: implement generation action
    