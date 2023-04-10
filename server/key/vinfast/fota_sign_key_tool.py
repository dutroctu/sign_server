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


TAG="vfota"

from server.fota import fotagentool as fotagentool
FOTA_SIGN_PRI_KEY=fotagentool.TOOL_FOTA_PRIV_KEY_FNAME
FOTA_SIGN_PUB_KEY=fotagentool.TOOL_FOTA_PUB_KEY_FNAME
REQUIRE_KEY = {
    FOTA_SIGN_PRI_KEY:".",
    # FOTA_SIGN_PUB_KEY:".",
}

REQUIRE_KEY_DESC = {
    FOTA_SIGN_PRI_KEY:"RSA Private key used to sign FOTA package",
    # FOTA_SIGN_PUB_KEY:"RSA Public key used to encrypt oem key",
}

KEY_TOOL_NAME = "vfota_sign"
class VinFotaSignKeyTool(KeyTool):

    def getName(self):
        return KEY_TOOL_NAME

    # return dic with key is file name and values is relative path (not include file)
    def get_require_keys(self):
        return REQUIRE_KEY
    
    def get_require_keys_desc(self):
        return REQUIRE_KEY_DESC
