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
from server.sign import signfactory as signfactory, signfota

from server.app import getProjectList
from server.app import getModelList
from server.common import DEFAULT_KEY_ID, ERR_INVALID_DATA
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

import server.key.vinfast as vinfast
import server.sign as sign
from server.fota import fotagentool as fotagentool

from server.app import DEBUG
TAG="SignProvision"
TOOL_NAME = "provision"
TOOL_DESC = "eCockpit provision"

COMMAND_TIMEOUT_MIN=30
COMMAND_TIMEOUT_SECOND=(COMMAND_TIMEOUT_MIN*60)

# toolg for signing
TOOL_ZIP = os.path.join(ROOT_DIR, "tool/provision/tool.zip")
AWS_ENDPOINT = os.path.join(ROOT_DIR, "tool/provision/aws.json")

# Sign script name
TOOL_SCRIPT = "sign.sh"

INPUT_IMAGE_TAG = "image"

PARAM_CSR="csr"
PARAM_FOTA_PASS_ENV="fota_pwd"
PARAM_VF_PASS_ENV="vf_pwd"

PARAM_ENDPOINT_ID="endpointid"
PARAM_ENDPOINT_ADDR="endpointaddr"

DEFAULT_ENPOINT="a22jgs7fwcgdkw-ats.iot.ap-southeast-1.amazonaws.com"
DEFAULT_ENPOINT_CA=os.path.join(ROOT_DIR, "tool/provision/aws/AmazoneRootCA1.pem")
DEFAULT_ENPOINT_PORT=8883
# Sign Request of Tbox
class SignRequestProvision(SignRequest):

    vf_key_id = None
    vf_key_info = None
    
    fota_enc_key_id = None
    fota_enc_key_info = None
    
    fota_sign_key_id = None
    fota_sign_key_info = None

    oem_key_id = None
    oem_key_info = None


    csr_data = None
    endpoint_id = None
    endpoint_addr = None
    
    key_working_folder = None
    def __init__(self, __request):
        super(SignRequestProvision, self).__init__(__request, TOOL_NAME)

        self.csr_data = None
        self.key_working_folder = None

        [self.fota_enc_key_id, self.fota_enc_key_info] = \
            self.getKeyInfo(request, "fota_enc_key_id", "fota_enc_key_name", vinfast.fota_enc_key_tool.KEY_TOOL_NAME)
        
        if self.fota_enc_key_info is None:
            self.getKeyInfo(request, "fota_enc_key_id", "fota_enc_key_name", keytool = vinfast.fota_enc_key_tool.KEY_TOOL_NAME, tool = signfota.FOTA_TOOL_NAME)
        
        [self.fota_sign_key_id, self.fota_sign_key_info] = \
            self.getKeyInfo(request, "fota_sign_key_id", "fota_sign_key_name", vinfast.fota_sign_key_tool.KEY_TOOL_NAME)
        
        if  self.fota_sign_key_info is None:
            self.getKeyInfo(request, "fota_sign_key_id", "fota_sign_key_name", keytool = vinfast.fota_sign_key_tool.KEY_TOOL_NAME, tool = signfota.FOTA_TOOL_NAME)

        [self.oem_key_id, self.oem_key_info] = \
            self.getKeyInfo(request, "oem_key_id", "oem_key_name", vinfast.oem_key_tool.KEY_TOOL_NAME)
        
        [self.vf_key_id, self.vf_key_info] = self.getKeyInfo(request, "vf_key_id", "vf_key_name", vinfast.vf_key_tool.KEY_TOOL_NAME)

        self.csr_data = common.extract_form_request(request, PARAM_CSR, is_int=False, default_data="")
        self.endpoint_id = common.extract_form_request(request, PARAM_ENDPOINT_ID, is_int=False, default_data=None)
        self.endpoint_addr = common.extract_form_request(request, PARAM_ENDPOINT_ADDR, is_int=False, default_data=None)

    def toString(self):
        str = super(SignRequestProvision, self).toString()
        # if (self.sign_id is not None):
        #     str += "sign_id: %s, " % self.sign_id
        # if (self.platform is not None):
        #     str += "platform: %s, " % self.platform
        # if (self.type is not None):
        #     str += "type: %s, " % self.type
        str += "\n"
        return str

    # return dic of keyinfo, with key is keytype, value is key_info
    def getListKeyInfo(self):
        return {
            "fota_enc_key_info":self.fota_enc_key_info,
            "fota_sign_key_info":self.fota_sign_key_info,
            "oem_key_info":self.oem_key_info,
            "vf_key_info":self.vf_key_info
            }

ITEM_OEM_KEY = "oemkey"
ITEM_ID = "id"
ITEM_NAME = "name"
ITEM_KEY1 = "key1"
ITEM_KEY2 = "key2"
ITEM_KEY3 = "key3"
ITEM_KEY4 = "key4"
class OemKey:
    id = None # id
    name = None # name
    key1 = None # each key level has different meaning, so not use array here, 
    key2 = None 
    key3 = None 
    key4 = None 

    def __init__(self, jobj=None):
        self.id = None
        self.name = None
        self.key1 = None
        self.key2 = None
        self.key3 = None
        self.key4 = None

        if jobj is not None:
            self.fromJsonObj(jobj)

   # Convert from json, change relative path to full path
    def fromJsonObj(self, jobj):
        if (DEBUG): logD("fromJson", TAG)

        id = common.getJsonObjData(jobj=jobj, name=ITEM_ID, default=None)
        
        self.id = int(id, 0)
        if (DEBUG): logD("id %s --> %d" % (id, self.id), TAG)

        self.name = common.getJsonObjData(jobj=jobj, name=ITEM_NAME, default=None)
        if (DEBUG): logD("name %s" % self.name, TAG)
    
        import binascii
        key1 = common.getJsonObjData(jobj=jobj, name=ITEM_KEY1, default=None)
        if (DEBUG): logD("key1 %s" % key1, TAG)
        if key1.startswith("0x"):
            key1 = key1[2:]
        self.key1 = binascii.unhexlify(key1)
        
        key2 = common.getJsonObjData(jobj=jobj, name=ITEM_KEY2, default=None)
        if (DEBUG): logD("key2 %s" % key2, TAG)
        if key2.startswith("0x"):
            key2 = key2[2:]
        self.key2 = binascii.unhexlify(key2)

        key3 = common.getJsonObjData(jobj=jobj, name=ITEM_KEY3, default=None)
        if (DEBUG): logD("key3 %s" % key3, TAG)
        if key3.startswith("0x"):
            key3 = key3[2:]
        self.key3 = binascii.unhexlify(key3)

        key4 = common.getJsonObjData(jobj=jobj, name=ITEM_KEY4, default=None)
        if (DEBUG): logD("key4 %s" % key4, TAG)
        if key4.startswith("0x"):
            key4 = key4[2:]
        self.key4 = binascii.unhexlify(key4)

    def validate(self):
        ret = common.ERR_NONE
        msg = ""
        if (self.key1 is None) or (len(self.key1) == 0):
            ret = common.ERR_INVALID_DATA
            msg = "invalid key1"
        
        if (self.key2 is None) or (len(self.key2) == 0):
            ret = common.ERR_INVALID_DATA
            msg = "invalid key2"
        
        
        if (self.key3 is None) or (len(self.key3) == 0):
            ret = common.ERR_INVALID_DATA
            msg = "invalid key3"

        
        if (self.key4 is None) or (len(self.key4) == 0):
            ret = common.ERR_INVALID_DATA
            msg = "invalid key4"
        
        return [ret, msg]


   # load param file, and return corresponding param list
    @staticmethod
    def loadOemKey(file):
        if (DEBUG): logD("loadOemKey %s" % file, TAG)
        loadparam = []

        if common.isValidString(file) is not None:
            if os.path.exists(file):
                log("Try to get param list from file", TAG)
                try:
                    import json
                    with open(file) as jf: # parse json file
                        jdata = json.load(jf)
                        if (DEBUG): logD("jdata %s" % jdata, TAG)
                        # parse each json object
                        jparamlist = common.getJsonObjData(jobj=jdata, name=ITEM_OEM_KEY, default=[])
                        if jparamlist is not None and len(jparamlist) > 0:
                            for jparam in jparamlist:
                                param = OemKey(jparam)
                                [ret, msg] = param.validate() # validate if data is valid
                                if ret == common.ERR_NONE:
                                    loadparam.append(param)
                                else:
                                    logE("Invalid param info, ret %d. %s" % (ret, msg), TAG)
                                    loadparam = None
                                    break
                            # return loadparam
                        else:
                            logE("Not found any param", TAG)
                except:
                    traceback.print_exc()
                    loadparam = None
            else:
                logE("load param file failed, file not exist", TAG)
                loadparam = [] # file not exist
        else:
            logE("load param file fail, invalid file", TAG)
            loadparam = None
        return loadparam

ITEM_PROVISION = "endpoint"
ITEM_DESC = "desc"
ITEM_DEFAULT = "default"
ITEM_ADDR = "addr"
ITEM_CA = "ca"
ITEM_PORT = "port"
class EndPoint:
    id = None # id
    name = None # name
    desc = None
    is_default = False 
    addr = None 
    ca = None 
    port = DEFAULT_ENPOINT_PORT 

    def __init__(self, jobj=None, default_ca=None):
        self.id = None
        self.name = None
        self.desc = None
        self.is_default = False
        self.addr = None
        self.ca = None
        self.port = DEFAULT_ENPOINT_PORT

        if jobj is not None:
            self.fromJsonObj(jobj, default_ca)

   # Convert from json, change relative path to full path
    def fromJsonObj(self, jobj, default_ca=None):
        if (DEBUG): logD("fromJson", TAG)

        self.id = common.getJsonObjData(jobj=jobj, name=ITEM_ID, default=None)
        if (DEBUG): logD("id %s" % self.id, TAG)

        self.name = common.getJsonObjData(jobj=jobj, name=ITEM_NAME, default=None)
        if (DEBUG): logD("name %s" % self.name, TAG)
    
        self.desc = common.getJsonObjData(jobj=jobj, name=ITEM_DESC, default=None)
        if (DEBUG): logD("desc %s" % self.desc, TAG)

        self.is_default = common.getJsonObjData(jobj=jobj, name=ITEM_DEFAULT, default=False)
        if (DEBUG): logD("is_default %d" % self.is_default, TAG)

        self.addr = common.getJsonObjData(jobj=jobj, name=ITEM_ADDR, default=None)
        if (DEBUG): logD("addr %s" % self.addr, TAG)

        self.ca = common.getJsonObjData(jobj=jobj, name=ITEM_CA, default=None)
        if self.ca is None:
            self.ca = default_ca
            log("Endpoint %s use default ca" % self.id, TAG)
        if (DEBUG): logD("ca %s" % self.ca, TAG)

        self.port = common.getJsonObjData(jobj=jobj, name=ITEM_PORT, default=DEFAULT_ENPOINT_PORT)
        if (DEBUG): logD("port %d" % self.port, TAG)    
        

    def validate(self):
        ret = common.ERR_NONE
        msg = ""

        if (self.addr is None) or (len(self.addr) == 0):
            ret = common.ERR_INVALID_DATA
            msg = "invalid addr"

        
        if (self.ca is None) or (len(self.ca) == 0):
            ret = common.ERR_INVALID_DATA
            msg = "invalid ca"
        
        return [ret, msg]

   # load param file, and return corresponding param list
    @staticmethod
    def loadAwsEndpoint(file):
        if (DEBUG): logD("loadAwsEndpoint %s" % file, TAG)
        loadparam = {}
        default_ca = None
        if common.isValidString(file) is not None:
            if os.path.exists(file):
                log("Try to get param list from file", TAG)
                try:
                    import json
                    with open(file) as jf: # parse json file
                        jdata = json.load(jf)
                        if (DEBUG): logD("jdata %s" % jdata, TAG)
                        # parse each json object
                        default_ca = common.getJsonObjData(jobj=jdata, name=ITEM_CA, default=None)
                        jparamlist = common.getJsonObjData(jobj=jdata, name=ITEM_PROVISION, default=[])
                        if jparamlist is not None and len(jparamlist) > 0:
                            for jparam in jparamlist:
                                param = EndPoint(jparam, default_ca)
                                [ret, msg] = param.validate() # validate if data is valid
                                if ret == common.ERR_NONE:
                                    loadparam[param.id] = param
                                else:
                                    logE("Invalid param info, ret %d. %s" % (ret, msg), TAG)
                                    loadparam = None
                                    break
                            # return loadparam
                        else:
                            logE("Not found any param", TAG)
                except:
                    traceback.print_exc()
                    loadparam = None
            else:
                logE("load param file failed, file not exist", TAG)
                loadparam = None # file not exist
        else:
            logE("load param file fail, invalid file", TAG)
            loadparam = None
        return [loadparam, default_ca]

# TBox signing tool
class SignProvision(SignTool):
    vf_dir = None
    oemkey_dir = None
    fotakey_dir = None
    fotakeyenc_dir = None
    aws_dir = None
    
    def getName(self, desc=False):
        return TOOL_NAME if not desc else TOOL_DESC

    # parse request
    def parse_request(self, request):
        return SignRequestProvision(request)

    # checi request
    def check(self, __req):
        [__code, __msg] = super(SignProvision, self).check(__req)
        if (__code != 0):
            return [__code, __msg]

        __result_str = ""
        __result_code = 0

        if __result_code == 0 and __req.fota_enc_key_id is None:
            __result_code = -1
            __result_str += "No fota_enc_key_id/name"

        if __result_code == 0 and __req.fota_sign_key_id is None:
            __result_code = -1
            __result_str += "No fota_sign_key_id/name"

        if __result_code == 0 and __req.vf_key_id == INVALID_KEY_ID:
            __result_code = -1
            __result_str += "invalid/not exist vf_key_id/name"

        if __result_code == 0 and __req.oem_key_id == INVALID_KEY_ID:
            __result_code = -1
            __result_str += "invalid/not exist oem_key_id/name"

            
        if (__result_code == 0):
            __result_str = "OK"

        return [__result_code, __result_str]


    
    def prepare_oemkey(self, fromfile, toFile):
        if (DEBUG): logD("prepare_oemkey fromfile %s to file %s" % (fromfile, toFile), TAG)
        ret = common.ERR_FAILED
        keylist = OemKey.loadOemKey(fromfile)
        noKeys = 0
        if (keylist is not None and len(keylist) > 0):
            if (DEBUG): logD("keylist %s" % str(keylist), TAG)
            ret = common.ERR_NONE
            try:
                with open(toFile, 'wb') as f:
                    for key in keylist:
                        bytes_val = key.id.to_bytes(12, 'little')
                        f.write(bytes_val)
                        if (key.key1 is not None) and (key.key2 is not None) and (key.key3 is not None) and (key.key4 is not None):
                            f.write(key.key1)
                            f.write(key.key2)
                            f.write(key.key3)
                            f.write(key.key4)
                        else:
                            logE("Invalid keylevel", TAG)
                            ret = common.ERR_FAILED
                            break
                        noKeys += 1
            except:
                traceback.print_exc()
                ret = common.ERR_EXCEPTION
        else:
            ret = common.ERR_NO_DATA
        
        return noKeys if ret == common.ERR_NONE else ret

    def prepare_endpoint(self, fromfile, id, addr):
        if (DEBUG): logD("prepare_endpoint fromfile %s id %s" % (fromfile, id), TAG)
        ret = None
        [endpoints, default_ca] = EndPoint.loadAwsEndpoint(fromfile)
        if addr is None or len(addr) == 0:
            if (endpoints is not None and len(endpoints) > 0):
                if (DEBUG): logD("endpoints %s" % str(endpoints), TAG)
                ret = common.ERR_NONE
                if id in endpoints:
                    ret = endpoints[id]
                else:
                    logE("id %s not exist" % id, TAG)
                    ret = None
            else:
                logE("Load enpoint %s failed %s" % fromfile, TAG)
                ret = None
        else:
            ret = EndPoint()
            ret.name = addr
            ret.ca = default_ca
            ret.port = DEFAULT_ENPOINT_PORT
        
        return ret

    def sign_provision(self, __req):

        signed_image_folder = os.path.join(__req.out_working_folder, "signed") # signed file is put in "output" folder
        common.mkdir(signed_image_folder)

        # prepare files to be signed/encrypt/...

        img_dir = os.path.join(__req.tool_working_folder, "input") # signed file is put in "output" folder
        common.mkdir(img_dir)

        oemkey_fpath = os.path.join(self.oemkey_dir, vinfast.oem_key_tool.OEM_KEY_FNAME) 
        oemkey_gen_fpath = os.path.join(self.oemkey_dir, "%s.bin" % vinfast.oem_key_tool.OEM_KEY_FNAME) 
        ret = self.prepare_oemkey(oemkey_fpath, oemkey_gen_fpath)
        if ret < 0:
            return SignResp(__req, ret, "Invalid oem key format")
        noOemKey = ret
        
        endpoint = self.prepare_endpoint(AWS_ENDPOINT, __req.endpoint_id, __req.endpoint_addr)
        if endpoint is None or endpoint.addr is None or len(endpoint.addr) == 0:
            return SignResp(__req, common.ERR_INVALID_ARGS, "Invalid endpoint")
        aws_ca_fpath = None
        if endpoint.ca is not None:
            aws_ca_fpath = os.path.join(self.aws_dir, "aws.cer") 
            if not common.write_string_to_file(aws_ca_fpath, endpoint.ca):
                logE("faile to write aws_ca_fpath to file", TAG, True)
                return SignResp(__req, -1, "prepare aws ca failed")
        else:
            aws_ca_fpath = DEFAULT_ENPOINT_CA
            
        no_file = 0
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
        csr_data_fpath = None
        if no_file == 0:
            if __req.csr_data is not None and len(__req.csr_data) > 0:
                csr_data_fpath = os.path.join(img_dir, "bootstrap.csr")
                if (DEBUG): logD("Write %s file %s" % (__req.csr_data, csr_data_fpath), TAG)
                if not common.write_string_to_file(csr_data_fpath, __req.csr_data):
                    logE("faile to write csr_data to file", TAG, True)
                    return SignResp(__req, -1, "prepare csr_data failed")
            else:
                logE("not found any file/csr_data", TAG, True)
                return SignResp(__req, -1, "not found any file/csr_data")


        __script = os.path.join(__req.tool_working_folder, TOOL_SCRIPT)

        if not os.path.exists(__script):
            logE("%s not found" % __script, TAG, True)
            return SignResp(__req, -1, "Not found script to sign")
        
        fota_sign_key_pwd=None
        vf_key_pwd=None
        import copy
        new_env = copy.deepcopy(os.environ)

        if __req.fota_sign_key_info is not None and __req.fota_sign_key_info.pwd is not None and len(__req.fota_sign_key_info.pwd) > 0:
            if (DEBUG): logD("Set password", TAG)
            fota_sign_key_pwd = __req.fota_sign_key_info.pwd
            new_env[PARAM_FOTA_PASS_ENV] = fota_sign_key_pwd

        if __req.vf_key_info is not None and __req.vf_key_info.pwd is not None and len(__req.vf_key_info.pwd) > 0:
            if (DEBUG): logD("Set password", TAG)
            vf_key_pwd = __req.vf_key_info.pwd
            new_env[PARAM_VF_PASS_ENV] = vf_key_pwd


        # build command to start signing
        command = "%s %s --csr=%s --output=%s --endpoint=\"%s\" --endpoint-port=\"%s\" --endpoint-ca=%s --fota-enc-key=%s --fota-sign-key=%s --fota-pwd=%s --oem-key=%s --no-oem-key=%d --vf-key=%s --vf-ca=%s --vf-pwd=%s " % (
            __script
            ,"-v" if DEBUG else ""
            , img_dir
            , signed_image_folder
            , endpoint.addr
            , endpoint.port
            , aws_ca_fpath
            , os.path.join(self.fotakeyenc_dir, vinfast.fota_enc_key_tool.FOTA_ENC_KEY_FNAME)
            , os.path.join(self.fotakey_dir, vinfast.fota_sign_key_tool.FOTA_SIGN_PRI_KEY)
            , PARAM_FOTA_PASS_ENV if fota_sign_key_pwd is not None else ""
            , oemkey_gen_fpath
            , noOemKey
            , os.path.join(self.vf_dir, vinfast.vf_key_tool.VF_ROOT_KEY)
            , os.path.join(self.vf_dir, vinfast.vf_key_tool.VF_ROOT_CA)
            , PARAM_VF_PASS_ENV if vf_key_pwd is not None else ""
           )
      
        log ("command: " + command, TAG, True)
        # start signing
        # __res = os.system(command)
        # run signing script
        try:
            import subprocess
            child = subprocess.run(command, shell=True, env=new_env, timeout=COMMAND_TIMEOUT_SECOND if COMMAND_TIMEOUT_SECOND > 0 else None)
            __res = child.returncode
        except:
            traceback.print_exc()
            return SignResp(__req, -1, "Sign failed, exception occurs")

        if (DEBUG): logD("command %d" % __res)
        if __res != 0 :
            logE("Signed failed with command %s, res %d" % (command, __res), TAG, True)
            return SignResp(__req, -1, "Signed failed %d" % __res)

        # pack output
        resp = self.packOutput(__req, signed_image_folder)

        return resp
    
    # do signing
    def do_sign(self, __req):
        # check paramater
        [__code, __msg] = self.check(__req)

        if (__code != 0):
            return SignResp(__req, __code, __msg)

        # extract tool to output folder
        [__code, __msg] = self.prepareTool(__req, TOOL_ZIP)

        if (__code != common.ERR_NONE):
            return SignResp(__req, __code, __msg)

        # Get key basing on key id, or use default one
        log ("Sign with vf key: %s" % __req.vf_key_id, TAG, True)
        log ("Sign with fota_enc_key_id: %s" % __req.fota_enc_key_id, TAG, True)
        log ("Sign with fota_enc_key_id: %s" % __req.fota_sign_key_id, TAG, True)
        log ("Sign with oem_key_id: %s" % __req.oem_key_id, TAG, True)
        
        self.vf_dir = os.path.join(__req.tool_working_folder, "vfkey")
        self.oemkey_dir = os.path.join(__req.tool_working_folder, "oemkey")
        self.fotakey_dir = os.path.join(__req.tool_working_folder, "fotakey")
        self.fotakeyenc_dir = os.path.join(__req.tool_working_folder, "fotakeyenc")
        self.aws_dir = os.path.join(__req.tool_working_folder, "aws")

        if os.path.exists(self.aws_dir):
            if (DEBUG): logD("Remove existing in %s to create new one" % self.aws_dir, TAG)
            common.rm_file_in_dir(self.aws_dir)
        else:
            common.mkdir(self.aws_dir)

        if (__req.vf_key_info != None):
            if os.path.exists(self.vf_dir):
                if (DEBUG): logD("Remove existing in %s to create new one" % self.vf_dir, TAG)
                common.rm_file_in_dir(self.vf_dir)
            else:
                common.mkdir(self.vf_dir)
            [__code, __msg] = self.prepareKey(__req, __req.vf_key_info, self.vf_dir)
           
        if  (__code == common.ERR_NONE) and __req.oem_key_info != None:
            if os.path.exists(self.oemkey_dir):
                if (DEBUG): logD("Remove existing in %s to create new one" % self.oemkey_dir, TAG)
                common.rm_file_in_dir(self.oemkey_dir)
            else:
                common.mkdir(self.oemkey_dir)
            [__code, __msg] = self.prepareKey(__req, __req.oem_key_info, self.oemkey_dir)

        if  (__code == common.ERR_NONE) and __req.fota_enc_key_info != None:
            if os.path.exists(self.fotakeyenc_dir):
                if (DEBUG): logD("Remove existing in %s to create new one" % self.fotakeyenc_dir, TAG)
                common.rm_file_in_dir(self.fotakeyenc_dir)
            else:
                common.mkdir(self.fotakeyenc_dir)
            [__code, __msg] = self.prepareKey(__req, __req.fota_enc_key_info, self.fotakeyenc_dir)

        if  (__code == common.ERR_NONE) and __req.fota_sign_key_info != None:
            if os.path.exists(self.fotakey_dir):
                if (DEBUG): logD("Remove existing in %s to create new one" % self.fotakey_dir, TAG)
                common.rm_file_in_dir(self.fotakey_dir)
            else:
                common.mkdir(self.fotakey_dir)
            [__code, __msg] = self.prepareKey(__req, __req.fota_sign_key_info, self.fotakey_dir)

        if __code == common.ERR_NONE:
            resp = self.sign_provision(__req)
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
        vf_key_list = keyMgr().get_all_keys(tool=TOOL_NAME, keytool = vinfast.vf_key_tool.KEY_TOOL_NAME)
        oem_key_list = keyMgr().get_all_keys(tool=TOOL_NAME, keytool = vinfast.oem_key_tool.KEY_TOOL_NAME)
        fota_enc_key_list = keyMgr().get_all_keys(tool=sign.signfota.FOTA_TOOL_NAME, keytool = vinfast.fota_enc_key_tool.KEY_TOOL_NAME)
        fota_sign_key_list = keyMgr().get_all_keys(tool=sign.signfota.FOTA_TOOL_NAME, keytool = vinfast.fota_sign_key_tool.KEY_TOOL_NAME)
        endpoint_list, _ = EndPoint.loadAwsEndpoint(AWS_ENDPOINT)
        return render_template(
            "sign/sign_provision.html"
            , login=is_login(request)
            , module="Provision"
            , project_list=getProjectList()
            , model_list=getModelList()
            , default_key_id=DEFAULT_KEY_ID
            , vf_key_list=vf_key_list
            , oem_key_list=oem_key_list
            , fota_enc_key_list=fota_enc_key_list
            , fota_sign_key_list=fota_sign_key_list
            , username=current_username()
            , toolname=TOOL_NAME
            , endpoint_list=endpoint_list if endpoint_list is not None else {}
            )
    def getKeyToolList(self):
        return [
                vinfast.fota_sign_key_tool.KEY_TOOL_NAME, 
                vinfast.fota_enc_key_tool.KEY_TOOL_NAME, 
                vinfast.oem_key_tool.KEY_TOOL_NAME,
                vinfast.vf_key_tool.KEY_TOOL_NAME
                ]

    def validate_key(self, key_req, key_dir, keypass, keytoolname=None):
        if (DEBUG): logD("validate_key %s" % keytoolname, TAG)
        if (DEBUG): logD("call parent to check", TAG)
        [ret, msg] = super(SignProvision, self).validate_key(key_req, key_dir, keypass, keytoolname)
        if ret == common.ERR_NONE:
            if keytoolname == vinfast.oem_key_tool.KEY_TOOL_NAME:
                oemkey_fpath = os.path.join(key_dir, vinfast.oem_key_tool.OEM_KEY_FNAME) 
                oemkey_gen_fpath = os.path.join(key_dir, "%s.bin" % vinfast.oem_key_tool.OEM_KEY_FNAME) 
                ret = self.prepare_oemkey(oemkey_fpath, oemkey_gen_fpath)
                if ret < 0:
                    msg = "Invalid %s" % vinfast.oem_key_tool.OEM_KEY_FNAME
                    logE(msg, TAG)
                else:
                    ret = common.ERR_NONE
            else:
                log("Skil checking %s" % (keytoolname), TAG)
        else:
            logE("Parent check failed %d %s" % (ret, msg), TAG)
        return [ret, msg]