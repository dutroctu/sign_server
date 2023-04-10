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
from server import applog
from server.applog import log
from server.applog import logE
from server.applog import logD
from server.app import get_resp
from server.app import getRootInputDir
from server.app import getRootOutputDir
from server.app import KEEP_OUTPUT_FILE
from server.database.key import KEY_DATA_TYPE_RAW
from server.database.key import KEY_SOURCE_IMPORT_API
from server.database.key import ALG_LIST
from server.key.key_mng import KEY_FOLDER_NAME
from server.key.key_mng import keyMgr
from server.key.key_mng import IKeyChangeListener
from server import key as key
import traceback
from server import common as common
from server.database.key_info import KeyInfo
from flask_login import login_required
from server.common import extract_form_request
import json
from server.app import DEBUG
TAG="keytool"

class KeyRequest(object):
    access_token = "" # for log in feature
    key_info = None
    in_working_folder = "" # caller's input data
    session = None # session
    upload_files = {} # key: id, value: list of file
    target_tool = None
    target_keytool = None
    def __init__(self):
        self.access_token = "" # for log in feature
        self.key_info = None
        self.in_working_folder = "" # caller's input data
        self.session = None # session
        self.upload_files = {} # key: id, value: list of file
        self.target_tool = None # key: id, value: list of file
        self.target_keytool = None # key: id, value: list of file
    
    def parse(self, request):
        if (DEBUG): logD("parse", TAG)
        # Parse request, build key info
        # TODO validate request info
        self.key_info = KeyInfo(name = extract_form_request(request, common.PARAM_NAME).strip(),
            tag = extract_form_request(request, common.PARAM_TAG).strip(),
            hint = extract_form_request(request, common.PARM_HINT).strip(),
            keyDB = None
            )
        
        self.key_info.title = extract_form_request(request, common.PARAM_TITLE, default_data="")
        self.key_info.title = self.key_info.title.strip() if self.key_info.title is not None else None

        prjs = extract_form_request(request, common.PARAM_PROJECT, getlist=True)
        self.key_info.project = str(prjs) if prjs is not None else None

        models = extract_form_request(request, common.PARAM_MODEL, getlist=True)
        self.key_info.model = str(models) if models is not None else None

        tools = extract_form_request(request, common.PARAM_TOOL, getlist=True)
        self.key_info.target_tool = str(tools) if tools is not None else None

        keytools = extract_form_request(request, common.PARAM_KEYTOOL, getlist=True)
        self.key_info.target_keytool = str(keytools) if keytools is not None else None

        self.access_token = extract_form_request(request, common.PARAM_ACCESS_TOKEN).strip()

        if self.key_info.name == None or len(self.key_info.name) == 0:
            return [common.ERR_INVALID_ARGS, "no key name"]

        if prjs == None or len(prjs) == 0:
            return [common.ERR_INVALID_ARGS, "no prjs"]
        
        if models == None or len(models) == 0:
            return [common.ERR_INVALID_ARGS, "no models"]
        
        if tools == None or len(tools) == 0:
            return [common.ERR_INVALID_ARGS, "no tools"]

        # if self.access_token == None or len(self.access_token) == 0:
        #     return [common.ERR_INVALID_ARGS, "no access_token"]

        #TODO: just get, not manage by session management yet, handle it to avoid risk of dup session id
        import server.sign.signfactory
        self.session = server.sign.signfactory.SignFactory.getSession() # get session, not push to session mng for managing yet
        
        if self.key_info.name == common.DEFAULT_KEY_ID:
            return [common.ERR_INVALID_ARGS, "invalid name, %s is reserve keyword" % self.key_info.name]
        
        self.in_working_folder = os.path.join(getRootInputDir(), self.session.uuid)
        common.mkdir(self.in_working_folder)
        self.out_working_folder = os.path.join(getRootOutputDir(), self.session.uuid)
        common.mkdir(self.out_working_folder)

        ret = common.ERR_NONE
        if (DEBUG): logD("request.files %s " % str(request.files), TAG)
        # logD("request.files.keys %s " % str(request.files.keys()), TAG)
        for (key, val) in request.files.items(True):
            if (DEBUG): logD("key %s" % str(key), TAG)
            if (DEBUG): logD("val %s" % str(val), TAG)

            if key is not None and len(str(key)) > 0:

                keydir = os.path.join(self.in_working_folder, key)
                if not os.path.exists(keydir):
                    common.mkdir(keydir)

                if val is not None and val.filename is not None and len(val.filename) > 0:
                    fname = common.normalize_fname(val.filename)
                    if fname is not None and len(fname) > 0:
                        fpath = os.path.join(keydir, fname)
                        if not os.path.exists(fpath):
                            if (DEBUG): logD("Save %s:%s to %s" % (key, fname, fpath), TAG)
                            val.save(fpath)
                            
                            if key not in self.upload_files.keys():
                                self.upload_files[key] = [fpath]
                            else:
                                self.upload_files[key].append(fpath)
                        else:
                            ret = common.ERR_EXISTED
                            break
        
        if ret != common.ERR_NONE:
            if not server.app.KEEP_OUTPUT_FILE:
                common.rmdirs(self.in_working_folder)
            return [ret, "Failed to parse file, error %d (%s)" % (ret, common.get_err_msg(ret))]
        
        if (DEBUG): logD("key_info: %s" % self.key_info.toString(), TAG)
        if (DEBUG): logD("upload_files: %s" % str(self.upload_files), TAG)

        return [common.ERR_NONE, "OK"]

    # clean up signing request data
    def clean(self):
        if (DEBUG): logD("KeyRequest: remove in_working_folder %s" % self.in_working_folder, TAG)
        if not KEEP_OUTPUT_FILE:
            common.rmdirs(self.in_working_folder)
        if (DEBUG): logD("KeyRequest: remove out_working_folder %s" % self.out_working_folder, TAG)
        if not KEEP_OUTPUT_FILE:
            common.rmdirs(self.out_working_folder)

    def toString(self, isFull=False):
        str = ""

        str += "\n"
        return str

   # check request info
    def validate(self):
        __result_str = ""
        __result_code = common.ERR_NONE

        if self.key_info is None:
            __result_code = common.ERR_INVALID_ARGS
            __result_str += "No keyinfo, "
        
        if self.key_info.name is None or len(self.key_info.name)  == 0:
            __result_code = common.ERR_INVALID_ARGS
            __result_str += "No name, "
        elif (not common.validate_usrname(self.key_info.name)):
            __result_code = common.ERR_INVALID_ARGS
            __result_str += "Invalid name, "
        

        if self.key_info.title is None or len(self.key_info.title)  == 0:
            __result_code = common.ERR_INVALID_ARGS
            __result_str += "No title, "


        if self.key_info.target_keytool is None or len(self.key_info.target_keytool) == 0:
            __result_code = common.ERR_INVALID_ARGS
            __result_str += "No target_keytool, "
        return [__result_code, __result_str]


class KeyTool(IKeyChangeListener):
    
    def __init__(self):
        keyMgr().registerListener(self)

    def getName(self):
        return None
    
    # return dic with key is file name and values is relative path (not include file)
    def get_require_keys(self):
        return None
    
    # return dic with key is file name and description
    def get_require_keys_desc(self):
        return None

    def get_html_render(self, req):
        return None

    # get help for tool
    def get_help(self, req, helpid):
        if (DEBUG): logD("get_help", TAG)
        
        desc = self.get_require_keys_desc()
        if desc is not None:
            from server.doc import convertToHtml
            help = ""
            for key, value in desc.items():
                help += "%s: %s\n" % (key, value)
        
            if (DEBUG): logD(help, TAG)
            if len(help) > 0:
                return convertToHtml(help)
            return help
        return None

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

        return [common.ERR_NONE, ""]

    # return error code and key request if success, error message otherwise
    def parse(self, request):
        if (DEBUG): logD("parse", TAG)
        key_req = KeyRequest()
        [ret, msg] = key_req.parse(request)
        if (DEBUG): logD("key_req.parse %d" % ret, TAG)
        # TODO: handle error case
        return [ret, key_req if ret == common.ERR_NONE else msg]

    # return error code and error message
    def do_generate_key(self, key_req):
        if (DEBUG): logD("do_generate_key", TAG)
        return [common.ERR_NOT_SUPPORT, "not support"]

    def finalize_key_generation(self, ret, key_req):
        if (DEBUG): logD("finalize_key_generation", TAG)
        return ret

    # return error code and  error message otherwise
    def generate_key(self, request):
        if (DEBUG): logD("generate_key", TAG)
        [ret, msg] = self.parse(request)
        if (DEBUG): logD("parse %d" % ret, TAG)

        if (ret == common.ERR_NONE) and msg is not None: # msg is key_req if success
            if (DEBUG): logD("Check if key %s exist" % msg.key_info.toString())
            is_exist = keyMgr().is_key_exist(msg.key_info)
            if (is_exist != common.ERR_NOT_FOUND):
                msg.clean()
                return [is_exist, "%s find result %d" % (msg.key_info.name, is_exist)]
            [ret, msg] = self.do_generate_key(msg)
        ret = self.finalize_key_generation(ret, msg)

        if (DEBUG): logD("generate_key %d" % ret, TAG)
        return [ret, msg]

    #
    # IMPORT KEY
    #
    def prepare_import_key(self, key_req, input_key_dir=None):
        if (DEBUG): logD("prepare_import_key", TAG)
        if (DEBUG): logD("Check if key %s exist" % key_req.key_info.toString())
        keytoolname = self.getName()
        keytools = ([keytoolname] if keytoolname is not None else None)
        if (DEBUG): logD("keytools %s" % str(keytools), TAG)
        is_exist = keyMgr().is_key_exist(key_req.key_info, keytools=keytools)
        if (is_exist != common.ERR_NOT_FOUND):
            return [is_exist, "%s find result %d" % (key_req.key_info.name, is_exist)]
        return [common.ERR_NONE, "OK"]


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
            files[key] = keypath

        if (DEBUG): logD("import_key ret %s" % str(files), TAG)
        keytoolname = self.getName()
        keytools = ([keytoolname] if keytoolname is not None else None)
        if (DEBUG): logD("keytools %s" % str(keytools), TAG)
        [ret, msg] = keyMgr().import_key(
            key_req.key_info,
             key_req.access_token, 
             input_key_dir, 
             self.getName(), 
             files, 
             keytools = keytools)

        if (DEBUG): logD("do_import_key ret %d" % ret, TAG)
        return [ret, msg]



    def finalize_import_key(self, ret, key_req):
        if (DEBUG): logD("finalize_import_key ret %d" % ret, TAG)
        return ret

    # return error code and key request if success, error message otherwise
    def import_key(self, request):
        if (DEBUG): logD("import_key", TAG)
        [ret, msg] = self.parse(request)
        key_req = None
        if ret == common.ERR_NONE:
            key_req = msg

        if (ret == common.ERR_NONE) and key_req is not None:
            if (DEBUG): logD("prepare_import_key", TAG)
            [ret, msg] = self.prepare_import_key(key_req, None)

        if (ret == common.ERR_NONE) and key_req is not None:
            if (DEBUG): logD("do_import_key", TAG)
            [ret, msg] = self.do_import_key(key_req, None)

        if (DEBUG): logD("finalize_import_key, ret %d" % ret, TAG)
        ret = self.finalize_import_key(ret, key_req)

        if (DEBUG): logD("ret %d, msg %s" % (ret, msg), TAG)
        return [ret, key_req if ret == common.ERR_NONE else msg]

    # return dic with key is file name and explanation for key
    def get_require_keys_info(self):
        return None


    # return array with 2 element: result of check, and string of checking message
    def check_key(self, keyid, isdetail=False):
        return [common.ERR_NOT_SUPPORT, "Not support checking"]