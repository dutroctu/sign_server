#!/usr/bin/env python
#
#  COMMON CLASS FOR SIGN REQUEST
#


from flask import Flask
from flask_restful import Api, Resource, reqparse
from flask import send_file
from flask import render_template
from flask import request, abort, jsonify, send_from_directory
from server.app import app
from server.app import getRootInputDir
from server.app import getRootOutputDir
from server.app import KEEP_OUTPUT_FILE
from server.sign.signresp import SignResp
import os
from server import applog as applog 
import shutil
from server import common as common
import traceback
# from server.key.key_mng import keyMgr
import zipfile
from io import BytesIO
import shutil
import subprocess

from server.app import getProjectList
from server.app import getModelList
from server.common import DEFAULT_KEY_ID
from server.common import INVALID_KEY_ID
from server.common import NONE_KEY_ID

from server.applog import log
from server.applog import logD
from server.applog import logE

from server import common as common

from server.key.key_mng import keyMgr
from server.storage import storageMgr
from server import database as database
from server.app import DEBUG
TAG="sign"

OUTPUT_ZIP_FNAME="signed.zip"

# Common signing request, used by many modules
class SignRequest(object):
    access_token = "" # for log in feature
    project = ""
    model = ""
    zip_output = False # if output is zip file, instead of redirecting to download page

    in_working_folder = "" # caller's input data
    out_working_folder = "" # output data when doing signing
    tool_working_folder = "" # path to tool folder
    # key_working_folder = "" # path to key dir

    files = {}
    file_path_list = {} # list of input file, dict of name (<input name=xxx>) and full path
    file_dir_list = {} # list of input file dir

    # TODO: FIXME should be session id instead and call SignFactor/SessionMgr to get session for using? 
    # (session should be controlled by SessionMng only)
    session = None # signing session
    # key_id = INVALID_KEY_ID
    is_api = False
    tool = None
    # key_info = None
    # file name of output signed file

    output_resp = False # output to response, not file
    def getSignFile(self, tag):
        if (tag is not None and tag in self.file_path_list):
            fname = os.path.basename(self.file_path_list[tag][0]) # TODO: FIXME: support multi files
            __tmp = os.path.splitext(fname)
            filename_sign = "%s_signed%s" %(__tmp[0], __tmp[1])
            return filename_sign
        return None
    
    # file name of file to be signed
    def getFileName(self, tag):
        if (tag is not None and tag in self.file_path_list):
            fname = os.path.basename(self.file_path_list[tag][0]) # TODO: FIXME: support multi files
            return fname
        return None

    def __init__(self, request, tool=None):
        if (DEBUG): logD("SignRequest init", TAG)
        from server.key.key_mng import keyMgr
        self.tool = tool
        # self.key_info = None
        # Parse request info
        self.project = request.form.get(common.PARAM_PROJECT)
        self.model = request.form.get(common.PARAM_MODEL)
        self.access_token = request.form.get(common.PARAM_ACCESS_TOKEN)
        zip = request.form.get(common.PARAM_ZIP_OUTPUT)
        if (DEBUG): logD("zip %s" %(zip))
        if common.PARAM_API in request.form: # call via api?
            self.is_api = request.form.get(common.PARAM_API)

        # check if key id is specified
        # if common.PARAM_KEY_ID in request.form:
        #     self.key_id = request.form.get(common.PARAM_KEY_ID)
        # else:
        #     key_name = common.extract_form_request(request, common.PARAM_KEY_NAME)
        #     if key_name is not None and len(key_name) > 0: #if key name, need to match with project and model
        #         if key_name == common.DEFAULT_KEY_ID:
        #             self.key_id = key_name
        #         else:
        #             self.key_info = keyMgr().get_key_by_name(key_name, project=self.project, model=self.model)
        #             if (self.key_info is not None):
        #                 self.key_id = self.key_info.id
        #             else:
        #                 self.key_id = INVALID_KEY_ID
        #     else:
        #         self.key_id = DEFAULT_KEY_ID

        # # TODO: search default key in db
        # if self.key_id == DEFAULT_KEY_ID:
        #     self.key_info = keyMgr().get_default_key(self.project, self.model, tool)
        #     if self.key_info is None:
        #         log("Not found default key, use default in tool if exists")

        self.zip_output = common.isZip(zip)
    
        if (DEBUG): logD("zip_output %s" %(self.zip_output))
        
        from server.sign import signfactory
        self.session = signfactory.SignFactory.getSession()

        self.in_working_folder = os.path.join(getRootInputDir(), self.project, self.session.uuid)
        self.out_working_folder = os.path.join(getRootOutputDir(), self.project, self.session.uuid)
        self.tool_working_folder = ""
        self.files = request.files
        self.file_path_list = {}
        self.file_dir_list = {}
        # logD("files %s" % str(self.files))
        # for (key, val) in self.files.items(True):
        #     if (DEBUG): logD("key %s" % str(key))
        #     if (DEBUG): logD("val %s" % str(val))
        #     fname = common.normalize_fname(val.filename)
        #     path = os.path.join(self.in_working_folder, fname)
        #     if key in self.file_path_list:
        #         self.file_path_list[key].append(path)
        #     else:
        #         self.file_path_list[key] = [path]
        #     value.save(path)

        self.output_resp = False

    # return dic of keyinfo, with key is keytype, value is key_info
    def getListKeyInfo(self):
        return None
    
    def getKeyInfo(self, request, param_key_id = None, param_key_name = None, keytool = None, tool=None):
        if (DEBUG): logD("getKeyInfo param_key_id %s param_key_name %s keytool %s" % (param_key_id, param_key_id, keytool), TAG)
        key_id = common.extract_form_request(request, param_key_id) if param_key_id is not None else None
        key_info = None
        if key_id is None or len(key_id) == 0:
            if (DEBUG): logD("no keyid, get from keyname", TAG)
            key_name = common.extract_form_request(request, param_key_name) if param_key_name is not None else None
            if key_name is not None and len(key_name) > 0: #if key name, need to match with project and model
                if key_name != DEFAULT_KEY_ID and key_name != NONE_KEY_ID:
                    key_info = keyMgr().get_key_by_name(
                                        key_name, 
                                        project=self.project, 
                                        model=self.model,
                                        tool=self.tool if tool is None else tool,
                                        keytool=keytool
                                        )
                    if (key_info is not None):
                        key_id = key_info.id
                    else:
                        # key_id = None
                        key_id = INVALID_KEY_ID
                else: # key name is default, let's search default key
                    key_id = key_name
                
            else: # no key id nor key name
                key_id = None
            
        elif key_id != DEFAULT_KEY_ID and key_id != NONE_KEY_ID: # not default key, try to search
            
            if (DEBUG): logD("get key from keyid %s" % key_id, TAG)
            key_info = keyMgr().get_key(key_id)
            if key_info is None:
                logE("not found keyid %s" % key_id)
                # key_id = None
                key_id = INVALID_KEY_ID
            else:
                key_id = key_info.id
        # else: search default key later

        if key_id == DEFAULT_KEY_ID:
            if (DEBUG): logD("get default", TAG)
            key_info = keyMgr().get_default_key(self.project, self.model, self.tool if tool is None else tool, keytool)
            if key_info is None:
                log("Not found default key, use default in tool if exists")
            else:
                key_id = key_info.id
        elif key_id == NONE_KEY_ID:
            key_id = None
            key_info = None

        return [key_id, key_info]


    def toString(self, isFull=False):
        str = ""
    
        if (self.session is not None):
            str += "session: %s, " % self.session.toString()
        if (self.project is not None):
            str += "project: %s, " % self.project
        if (isFull):
            if (self.model is not None):
                str += "model: %s, " % self.model
            if (self.file_path_list is not None):
                str += "file_path_list: %s, " % str(self.file_path_list)
            if (self.access_token is not None):
                str += "access_token: %s, " % self.access_token
            if (self.in_working_folder is not None):
                str += "in_working_folder: %s, " % self.in_working_folder
            if (self.out_working_folder is not None):
                str += "out_working_folder: %s, " % self.out_working_folder

        str += "\n"
        return str

    # clean up signing request data
    def clean(self):
        if (DEBUG): logD("SignRequest: remove in_working_folder %s" % self.in_working_folder)
        common.rmdirs(self.in_working_folder)
        if (DEBUG): logD("SignRequest: remove out_working_folder %s" % self.out_working_folder)
        common.rmdirs(self.out_working_folder)
        #download folder will be clean in SignResp

    def getSignInfo(self):
        return None

# Common class for sign tool
class SignTool(object):
    # parse request
    def parse_request(self, request):
        return SignRequest(request)
    
    def handle_error(self):
        pass

    def getName(self):
        return None

    def get_html_render_for_manual_sign(self, __req):
        return "Unknown template"

    # check request info
    def check(self, __req):
        __result_str = ""
        __result_code = 0

        if __req.project is None or len(__req.project) == 0:
            __result_code = -1
            __result_str += "No project, "
        else :
            if __req.project not in getProjectList():
                __result_code = -1
                __result_str += "project %s not support, " % (__req.project )

        if __req.model is None or len(__req.model) == 0:
            __result_code = -1
            __result_str += "No model, "
        else :
            if __req.model not in getModelList():
                __result_code = -1
                __result_str += "model %s not support, " % (__req.model )

        # if __req.file_path_list is None or len(__req.file_path_list) == 0:
        #     __result_code = -1
        #     __result_str += "No file, "

        # if __req.key_id == INVALID_KEY_ID:
        #     __result_code = -1
        #     __result_str += "invalid/not exist key id/keyname"

        # if (__result_code == 0):
        #     __result_str = "OK"

        return [__result_code, __result_str]

    # do some preparation before signing
    def prepare(self, __req):
        if (DEBUG): logD("prepare: %s" % __req.toString(), TAG)
        # check paramater
        [__code, __msg] = self.check(__req)

        if (__code != 0):
            logE("prepare failed %d.%s" % (__code, __msg), TAG)
            return [__code, __msg]


        # make working folder for session
        common.mkdir(__req.in_working_folder)
        common.mkdir(__req.out_working_folder)

        # save upload file to input folder
        try:
            if (DEBUG): logD("files %s" % str(__req.files), TAG)
            for (key, val) in __req.files.items(True):
                if (DEBUG): logD("key %s" % str(key), TAG)
                if (DEBUG): logD("val %s" % str(val), TAG)
                if val.filename is not None and len(val.filename) > 0:
                    fname = common.normalize_fname(val.filename)
                    dir = os.path.join(__req.in_working_folder, key)
                    if not os.path.exists(dir):
                        common.mkdir(dir)
                        __req.file_dir_list[key] = dir
                    path = os.path.join(dir, fname)
                    if (DEBUG): logD("path %s" % path, TAG)
                    if key in __req.file_path_list:
                        __req.file_path_list[key].append(path)
                    else:
                        __req.file_path_list[key] = [path]
                    val.save(path)
            # for key, value in __req.files.items(True) :
            #     fname = common.normalize_fname(value.filename)
            #     if (key in __req.file_path_list):
            #         if (DEBUG): logD("save file to: %s" % __req.file_path_list[fname])
            #         value.save(__req.file_path_list[fname])
        except:
            traceback.print_exc()
            return [-1, "Failed to save uploaded files"]
        
        # logD("file_path_list: %s" % __req.file_path_list)
        if (DEBUG): logD("Prepare ok", TAG)
        return [0, "OK"]

    def prepareTool(self, __req, tool_path, should_copy=True):
        # extract tool to output folder
        
        if not os.path.exists(tool_path):
            logE("tool_path %s not found" % tool_path, TAG, True)
            return [common.ERR_NOT_FOUND, "Not found tool script"]
        
        try:
            if should_copy:
                __req.tool_working_folder = os.path.join(__req.out_working_folder, "tool")
                if common.isZipFile(tool_path):
                    if (DEBUG): logD("extract tool from %s to %s" %(tool_path, __req.tool_working_folder))
                    with zipfile.ZipFile(tool_path, 'r') as zip_ref:
                        zip_ref.extractall(__req.tool_working_folder)
                else:
                    shutil.copy(tool_path, self.tool_working_folder)
                subprocess.call(['chmod', '-R', '0755', __req.tool_working_folder])
            else:
                __req.tool_working_folder = tool_path

            if not os.path.exists(__req.tool_working_folder):
                logE("final tool path %s not found" % __req.tool_working_folder, TAG, True)
                return [common.ERR_FAILED, "Prepare tool failed"]

            return [common.ERR_NONE, "OK"]
        except:
            traceback.print_exc()
            return [common.ERR_EXCEPTION, "Failed to prepare tool, exception occurs"]

    def prepareKey(self, __req, key_info, key_dir, fnames=None):
        # Get key basing on key id, or use default one
        log ("prepareKey: %s" % key_dir, TAG, True)
        if fnames is not None:
            log("prepare key with fname: %s" % str(fnames), TAG)
        ret = [common.ERR_FAILED, "Something wrong"]

        # logD("key_info %s" % key_info.toString())
        if (key_info != None):
            try:
                # COPY KEY DATA TO OUTPUT FOLDER.
                # FIXME: SHOULD PROTECT/ENCRYPT IT?
                # TODO: Need to make sure that new key is used, not default one
                log("Get key", TAG)
                if (key_info.data_type == database.key.KEY_DATA_TYPE_FILE):
                    if ((key_info.files is not None and len(key_info.files) > 0) or 
                        ((key_info.fids is not None and len(key_info.fids) > 0))):
                        if len(key_info.fids) > 0:
                            no_key = 0
                            for fname, fid in key_info.fids.items():
                                if fnames is None or fname in fnames:
                                    fpath = os.path.join(key_dir, fname)
                                    retDecrypt = storageMgr().readFile(fid, fpath)
                                    if retDecrypt != common.ERR_NONE or not os.path.exists(fpath):
                                        ret = [retDecrypt, "Failed to decrypt"]
                                        raise ValueError("Failed to decrypt %s" % fid)
                                    if common.isZipFile(fpath):
                                        if (DEBUG): logD("key %s is zip file, unzip it" % fpath, TAG)
                                        if not common.unzip_file(fpath, key_dir):
                                            ret = [common.ERR_FAILED, "unzip key failed"]
                                            raise ValueError("unzip key failed %s" % fid)
                                    no_key += 1
                                else:
                                    if (DEBUG): logD("Skip fname %s" % fname, TAG)
                            
                            if no_key > 0:
                                if (DEBUG): logD("Found %d keys" % no_key, TAG)
                                ret = [common.ERR_NONE, ""] # WELL DONE
                            else:
                                logE("Not found any key", TAG)
                                ret = [common.ERR_NO_DATA, "not found key"]
                            
                        elif len(key_info.files) > 0:
                            for fname, fpath in key_info.files.items():
                                if fnames is None or fname in fnames:
                                    if (DEBUG): logD("Copy %s from %s to %s" % (fname, fpath, key_dir))
                                    from server.key.key_mng import keyMgr
                                    shutil.copy(keyMgr().get_full_key_path(fpath), key_dir)
                                    no_key += 1
                                else:
                                    if (DEBUG): logD("Skip fname %s" % fname, TAG)
                            
                            if no_key > 0:
                                if (DEBUG): logD("Found %d keys" % no_key, TAG)
                                ret = [common.ERR_NONE, ""] # WELL DONE
                            else:
                                logE("Not found any key", TAG)
                                ret = [common.ERR_NO_DATA, "not found key"]
                            
                        else:
                            # return SignResp(__req, -1, "no key to sign")
                            ret = [common.ERR_NO_DATA, "no key to sign"]
                        # if ret[0] == common.ERR_NONE:
                        #     __req.key_working_folder = key_dir
                    else:
                        # return SignResp(__req, -1, "Invalid key data")
                        ret = [common.ERR_INVALID_DATA, "Invalid key data"]
                else:
                    # return SignResp(__req, -1, "Not suitable key")
                    ret = [common.ERR_INVALID_DATA, "Not suitable key"]

                # prepare public key id
                log("Get public key", TAG)
                if key_info.pubfids is not None and len(key_info.pubfids) > 0:
                    ret2 = common.ERR_NONE
                    msg = "OK"
                    for fid in key_info.pubfids:
                        metafile = storageMgr().readMetaFile(fid)
                        if metafile is None:
                            logE("read meta for public fid %s failed" % fid, TAG)
                            ret2 = common.ERR_FAILED
                            msg = "read meta public fid failed"
                            break
                        fpath = os.path.join(key_dir, metafile.fname)
                        if (DEBUG): logD("temp fid %s fpath %s" % (fid, fpath), TAG)
                        ret2 = storageMgr().readFile(fid, fpath)
                        if ret2 != common.ERR_NONE:
                            logE("read pub fid %s failed" % fid, TAG)
                            msg = "read pub fid %s failed"
                            break
                    ret = [ret2, msg]
            except:
                traceback.print_exc()
                ret = [common.ERR_EXISTED, "Exception occur"]
        else:
            # return SignResp(__req, -1, "Invalid key id")
            ret = [common.ERR_INVALID_DATA, "Invalid key id"]
        return ret

    # real signing
    def do_sign(self, __req):
        applog.log("Do nothing")
        return SignResp(__req, -1, "Not support")

    # post steps to do signing
    def finish(self, resp):
        ret = False
        if (resp is not None):
            if (DEBUG): logD("do finish resp: %s" % resp.toString())
            from server.sign import signfactory
            ret = resp.finalize()
            
            if (ret): # all well, save session 
                signfactory.SignFactory.pushSession(resp.sign_req.session)
            else: # failed, clear data
                if (not KEEP_OUTPUT_FILE):
                    resp.clean()
                # clean up session
                signfactory.SignFactory.clearSession(resp.sign_req.session)

        return ret
    
    # do signing
    def sign(self, __req):
        [__code, __msg] = self.prepare(__req) # prepare
        if (__code == 0):
            resp = self.do_sign(__req) # do signing
        else:
            resp = SignResp(__req, -1, __msg)

        self.finish(resp) # finalize result
        return resp

    def getKeyToolList(self):
        return None

    def clean(self,__req):
        if (DEBUG): logD("SignTool: clean request %s" % __req.toString(), TAG)
        __req.clean()

    def validate_key(self, key_req, key_dir, keypass, keytoolname=None):
        if (DEBUG): logD("validate_key DEFAULT", TAG)
        ret = common.ERR_NOT_SUPPORT
        msg = "Not support"
        if keytoolname is not None and len(keytoolname) > 0:
            from server.key.key_mng import get_keytool_from_name
            keytoools = self.getKeyToolList()
            if keytoools is not None:
                if (DEBUG): logD("keytoools %s" % str(keytoools), TAG)
                if keytoolname in keytoools:
                    keytool = get_keytool_from_name(keytoolname)
                    if keytool is not None:
                        return keytool.validate_key(key_req = key_req, keypass = keypass, input_key_dir=key_dir)
                else:
                    msg = "valid key failed, keytool %s not supported by sign tool '%s'" % (keytoolname, self.getName())
                    ret = common.ERR_NOT_SUPPORT
                    logE(msg, TAG)
            else:
                msg = "sign tool has no keytoools, keytool %s not supported by sign tool '%s'" % (keytoolname, self.getName())
                ret = common.ERR_NOT_SUPPORT
                logE(msg, TAG)
        return [ret, msg]

    def packOutput(self, __req, output_dir):
        log("sign output file %s" % output_dir, TAG, True) # output_file is full signed binaries, to be used by caller for next signing steps
        if not os.path.exists(output_dir):
            logE("output %s not found" % output_dir, TAG, True)
            return SignResp(__req, -1, "Not found output")
        else:
            # fname = os.path.basename(output_dir)
            # zfname = "%s.zip" % fname
            zfname = OUTPUT_ZIP_FNAME
            zpath = os.path.join(output_dir, zfname)
            ret = common.zipfolder(output_dir, zpath)
            if (not ret) or not os.path.exists(zpath):
                return SignResp(__req, -1, "Failed to zip data")

        resp = SignResp(__req, 0, "OK")
        
        if resp.copy_to_download(zfname, zpath):

            # well done, setup data to be response to caller
            __req.session.set_data(resp) # assume that session is already checked before this function
        else:
            resp.set_response_msg(-1, "Failed to generate download file")

        return resp

    # get help, return html string or None on error
    def get_help(self, request):
        return None

    # get download file, return path file to download or None on error
    def get_download_file(self, request):
        return None