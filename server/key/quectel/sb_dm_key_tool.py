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

TAG="quectel_sb"


DM_OEM_ROOTCA_KEY_FNAME = "oem_rootca.key"
DM_OEM_ROOTCA_CERT_FNAME = "oem_rootca.cer"
DM_OEM_ATTEST_CERT_FNAME = "oem_attestationca.cer"
DM_OEM_ATTEST_KEY_FNAME = "oem_attestationca.key"


REQUIRE_KEY = {
    DM_OEM_ROOTCA_KEY_FNAME:".",
    DM_OEM_ROOTCA_CERT_FNAME:".",
    DM_OEM_ATTEST_CERT_FNAME:".",
    DM_OEM_ATTEST_KEY_FNAME:".",
    }

KEY_TOOL_NAME = "quectel_sb_dm"

REQUIRE_KEY_DESC = {
    DM_OEM_ROOTCA_KEY_FNAME:"Root CA key",
    DM_OEM_ROOTCA_CERT_FNAME:"Root CA cert",
    DM_OEM_ATTEST_CERT_FNAME:"Attestion cert",
    DM_OEM_ATTEST_KEY_FNAME:"Attestion key",
}
# DM verity may exist in dm/ folder when upload bulk of tbox key, so it needs to be handle different
class QuectelSbDMKeyTool(KeyTool):

    def getName(self):
        return KEY_TOOL_NAME

    # return dic with key is file name and values is relative path (not include file)
    def get_require_keys(self):
        return REQUIRE_KEY
    

    def get_require_keys_desc(self):
        return REQUIRE_KEY_DESC
        
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
            # search in . or in dm/ (for the case that dm key is uploaded together with attestion key)
            if not os.path.exists(os.path.join(input_key_dir, root, key)) and not os.path.exists(os.path.join(input_key_dir, root, "dm", key)):
                logE("Validate key failed, not found %s" % key, TAG)
                return [common.ERR_NOT_FOUND, "Not found %s" % key]


        return [common.ERR_NONE, ""]

    def do_import_key(self, key_req, input_key_dir=None):
        if (DEBUG): logD("do_import_key", TAG)
        # validate_key must be called FIRST!!!!!!!!!!!!! 
        # to avoid call to much times
        require_keys = self.get_require_keys()
        if require_keys is None:
            return [common.ERR_NOT_SUPPORT, "not support"]

        if input_key_dir is None or not os.path.exists(input_key_dir):
            return [common.ERR_NOT_FOUND, "no key dir, or key dir not exist"]
        
        files = {}
        for key,root in require_keys.items():
            keypath = os.path.join(input_key_dir, root, key)
            # search in . or in dm/ (for the case that dm key is uploaded together with attestion key)
            if not os.path.exists(keypath):
                keypath = os.path.join(input_key_dir, root, "dm", key)
            if os.path.exists(keypath):
                files[key] = keypath
            else:
                logE("Not found '%s'" % key, TAG)
                return [common.ERR_NOT_FOUND, "Not found '%s'" % key]

        if len(files) > 0:
            if (DEBUG): logD("import_key ret %s" % str(files), TAG)
            if (DEBUG): logD("import_key ret %s" % str(files), TAG)
            keytoolname = self.getName()
            keytools = ([keytoolname] if keytoolname is not None else None)
            if (DEBUG): logD("keytools %s" % str(keytools), TAG)
            [ret, msg] = keyMgr().import_key(key_req.key_info, key_req.access_token, input_key_dir, self.getName(), files, keytools=keytools)
        else:
            ret = common.ERR_NO_DATA
            msg = "not key to import"
        
        if (DEBUG): logD("do_import_key ret %d" % ret, TAG)
        return [ret, msg]