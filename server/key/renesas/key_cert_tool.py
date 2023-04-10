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

from server.storage.storage_mgr import storageMgr

TAG="renesaskeycert"

RENESAS_KEY_CERT_TOOL_NAME = "renesas_key_cert"

MAX_NUMER_KEY = 4

NV_COUNTER_TRUST_ID = 1
NV_COUNTER_NON_TRUST_ID = 2

 # ID=1:0-31, ID=2:0-223
NV_COUNTER_VALUE = {
    NV_COUNTER_TRUST_ID:[0, 31],
    NV_COUNTER_NON_TRUST_ID:[0, 223]
    }

PARAM_NUM_KEY = "num_key"
PARAM_NV_COUNTER_ID = "nv_counter_id"
PARAM_NV_COUNTER_VAL = "nv_counter_val" # ID=1:0-31, ID=2:0-223

PARAM_ROOT_KEY_FILE="cert-keypair"
PARAM_ROOT_KEY_PASS="cert-keypair-pwd"
PARAM_AES_ENC_KEY="aes-enc-key"
PARAM_AES_IV_GET="aes-iv-get"

PARAM_HASH_OUT="hash-out"

PARAM_NEXT_PUB_KEY_FILE="next-cert-pubkey"
PARAM_NEXT_PUB_KEY_PASS="next-cert-pubkey-pwd"

RENESAS_TOOL_DIR_NAME="renesas_tools"
SIGNING_TOOL_ZIP = "signingtool.zip"
SIGNING_TOOL_SCRIPT = "sign.sh"

KEY_CERT_CFG_FNAME = "sb_key_cert.cfg"
KEY_CERT_BIN_FNAME = "sb_key_cert.bin"

RENESAS_SIGN_TOOL_ZIP_PATH = os.path.join(getRootToolDir(), RENESAS_TOOL_DIR_NAME, SIGNING_TOOL_ZIP)

COMMAND_TIMEOUT_MIN = 1
COMMAND_TIMEOUT_SECOND = (COMMAND_TIMEOUT_MIN * 60)


UNKNOWN_TYPE = 0
KEY_CERTIFICATE_TYPE = 1
CONTENT_CERTIFICATE_TYPE = 2

#
# Renesas key info
#
class RenesasKeyInfo:
    # common info
    type = UNKNOWN_TYPE
    nv_counter_id = 0
    nv_counter_val = 0
    hash_out = {}
    out_cert_file = ""
    jdata = None
    def __init__(self):
        self.nv_counter_id = 0
        self.nv_counter_val = 0
        self.hash_out = {}
        self.type = UNKNOWN_TYPE
        self.out_cert_file = ""
        self.jdata = None

    # convert to json string, return json string on success, None otherwise
    def toJsonObj(self):
        jdata = {
            "type":self.type,
            "nv_counter_id":self.nv_counter_id,
            "nv_counter_val":self.nv_counter_val,
            "out_cert_file":self.out_cert_file,
            "hash_out":self.hash_out,
            }
        return jdata
    
    def toJson(self):
        jdata = self.toJsonObj()
        try:
            jstring = json.dumps(jdata)
            return jstring
        except:
            traceback.print_exc()
            logE("Meta file: Convert to json failed", TAG)
            return None

    # parse json string, return ERR_NONE on success, error code otherwise
    def fromJson(self, val):
        try:
            jdata = json.loads(val)

            # parse data
            self.type = jdata["type"] if "type" in jdata else UNKNOWN_TYPE
            self.nv_counter_id = jdata["nv_counter_id"] if "nv_counter_id" in jdata else 0
            self.nv_counter_val = jdata["nv_counter_val"] if "nv_counter_val" in jdata else 0
            self.out_cert_file = jdata["out_cert_file"] if "out_cert_file" in jdata else 0
            self.hash_out = jdata["hash_out"] if "hash_out" in jdata else {}
            self.jdata = jdata
            return common.ERR_NONE
        except:
            traceback.print_exc()
            logE("Meta file: Parse from json failed %s " % val, TAG)
            return common.ERR_EXCEPTION

#
# Key cert info
#
class RenesasKeyCertInfo(RenesasKeyInfo):
    num_key = 0
    hbkid = 0
    keypair = {}
    keypair_pwd = {}
    next_cert_pubkey = ""
    next_cert_privkey = ""
    def __init__(self):
        self.num_key = 0
        self.hbkid = 0
        self.keypair = {}
        self.keypair_pwd = {}
        self.next_cert_pubkey = ""
        self.next_cert_privkey = ""

    # convert to json string, return json string on success, None otherwise
    def toJsonObj(self):
        jcommondata = super(RenesasKeyCertInfo, self).toJsonObj()
        jkeydata = {
            "num_key":self.num_key,
            "hbkid":self.hbkid,
            "next_cert_pubkey":self.next_cert_pubkey,
            "next_cert_privkey":self.next_cert_privkey,
            "keypair":self.keypair,
            "keypair_pwd":self.keypair_pwd
            }
        jdata = {**jcommondata, **jkeydata}
        return jdata

    # parse json string, return ERR_NONE on success, error code otherwise
    def fromJson(self, val):
        super(RenesasKeyCertInfo, self).fromJson(val)
        try:
            jdata = self.jdata

            # parse data
            self.num_key = jdata["num_key"] if "num_key" in jdata else 0
            self.hbkid = jdata["hbkid"] if "hbkid" in jdata else 0
            self.next_cert_pubkey = jdata["next_cert_pubkey"] if "next_cert_pubkey" in jdata else 0
            self.next_cert_privkey = jdata["next_cert_privkey"] if "next_cert_privkey" in jdata else 0
            self.keypair = jdata["keypair"] if "keypair" in jdata else {}
            self.keypair_pwd = jdata["keypair_pwd"] if "keypair_pwd" in jdata else {}
            self.jdata = jdata
            return common.ERR_NONE
        except:
            traceback.print_exc()
            logE("Meta file: Parse from json failed %s " % val, TAG)
            return common.ERR_EXCEPTION

#
# Request to generate key cert
#
class RenesasKeyCertRequest(KeyRequest):
    pwd = ""
    num_key = 0
    nv_counter_id = 0
    nv_counter_val = 0
    hbkid = 0
    keypair = {}
    keypair_pwd = {}
    hash_out = {}
    next_cert_pubkey = None
    next_cert_privkey = None
    out_cert_file = ""
    type = UNKNOWN_TYPE
    def __init__(self):
        super(RenesasKeyCertRequest, self).__init__()
        self.pwd = ""
        self.num_key = 0
        self.nv_counter_id = 0
        self.nv_counter_val = 0
        self.hbkid = 0
        self.keypair = {}
        self.keypair_pwd = {}
        self.hash_out = {}
        self.next_cert_pubkey = None
        self.next_cert_privkey = None
        self.out_cert_file = ""
        self.type = UNKNOWN_TYPE

    # parse request
    def parse(self, request):
        if (DEBUG): logD("RenesasKeyCertRequest parse", TAG)
        ret = common.ERR_FAILED
        msg = ""
        [ret, msg] = super(RenesasKeyCertRequest, self).parse(request)

        if ret != common.ERR_NONE:
            logE("RenesasKeyCertRequest supper failed %d - %s" % (ret, msg), TAG)
            return [ret, msg]

        # extract the number of key
        self.num_key = common.extract_form_request(request, PARAM_NUM_KEY, is_int=True, default_data=1)
        self.nv_counter_id = common.extract_form_request(request, PARAM_NV_COUNTER_ID, is_int=True, default_data=-1)
        self.nv_counter_val = common.extract_form_request(request, PARAM_NV_COUNTER_VAL, is_int=True, default_data=-1)
        
        if self.num_key < 1 or self.num_key > 4:
            logE("invalid/no num_key%d" % self.num_key, TAG)
            return [common.ERR_INVALID_ARGS, "invalid/no num_key"]
        
        if self.nv_counter_id not in NV_COUNTER_VALUE:
            logE("invalid/no nv-counter id %d" % self.nv_counter_id, TAG)
            return [common.ERR_INVALID_ARGS, "invalid/no nv-counter id"]
        
        if self.nv_counter_val < NV_COUNTER_VALUE[self.nv_counter_id][0] or self.nv_counter_val > NV_COUNTER_VALUE[self.nv_counter_id][1]:
            logE("invalid/no nv-counter value %d" % self.nv_counter_val, TAG)
            return [common.ERR_INVALID_ARGS, "invalid/no nv-counter value"]

        # check target key tool
        if self.key_info.target_keytool is None:
            if (DEBUG): logD("not key tool, set default to %s" % RENESAS_KEY_CERT_TOOL_NAME, TAG)
            self.key_info.target_keytool = str([RENESAS_KEY_CERT_TOOL_NAME]) 

        # key dir
        keydir = os.path.join(self.in_working_folder, "keydir")
        common.mkdir(keydir)

        # [KEY-CFG]
        # cert-keypair = sbu_input/root_key.pem
        # cert-keypair-pwd =
        # hbk-id = 2
        # nvcounter-id = 1
        # nvcounter-val = 0
        # next-cert-pubkey = sbu_input/sb_key_pub.pem
        # cert-pkg = sbu_output/sb_key_cert.bin 

        count = 1
        while count <= self.num_key :
            name = "%s%d" % (PARAM_ROOT_KEY_FILE, count)
            keyname = "%s%d" % (PARAM_ROOT_KEY_PASS, count)
            if (DEBUG): logD("name %s" % name, TAG)
            if (DEBUG): logD("keyname %s" % keyname, TAG)
            if (DEBUG): logD("upload_files %s" % str(self.upload_files), TAG)

            pwdpath = None
            pwd = None
            keypair = None # [fid or None, # path to file]
            keypair_pwd = None # [fid or None, # path to file]

            # upload key
            if name in self.upload_files and len(self.upload_files[name]) > 0:
                keypair = [None, self.upload_files[name][0]] # uhm, asume that upload_files contains valid path, as being checked by key_tool
                keypair_pwd = [None, common.extract_form_request(request, keyname, default_data="")]
            else: # get key using keyid in form request
                keypair_id = common.extract_form_request(request, name, default_data=None)
                if keypair_id is not None and keypair_id != common.NONE_KEY_ID:
                    key_info = keyMgr().get_key(keypair_id)
                    if key_info is not None:
                        if key_info.fids is not None and len(key_info.fids) > 0:
                            from server.key.renesas.root_key_tool import ROOT_SIGN_KEY_FNAME
                            if ROOT_SIGN_KEY_FNAME in key_info.fids:
                                fid = key_info.fids[ROOT_SIGN_KEY_FNAME]
                                fidpath = os.path.join(self.in_working_folder, ROOT_SIGN_KEY_FNAME)
                                # FIXME: Risk of fidpath file existed????
                                ret = storageMgr().readFile(fid, fidpath)
                                if ret == common.ERR_NONE:
                                    keypair = [fid, fidpath]
                                    keypair_pwd = [fid, key_info.pwd] if key_info.pwd is not None and len(key_info.pwd) > 0 else None
                                else:
                                    msg = "readFile key for %s failed, fid %s not found" % (name, fid)
                                    break
            
            if keypair is not None and len(keypair) > 1:
                self.keypair[name] = keypair
                if keypair_pwd is not None and len(keypair_pwd) > 1: # 2 params
                    pwdpath = os.path.join(keydir, keyname)
                    if common.write_string_to_file(pwdpath, keypair_pwd[1]):
                        keypair_pwd[1] = pwdpath
                        if (DEBUG): logD("pwdpath %s" % pwdpath, TAG)
                        self.keypair_pwd[name] = keypair_pwd
                    else:
                        ret = common.ERR_FAIELD
                        msg = "failed to prepare pwd"
                        break
                else:
                    self.keypair_pwd[name] = None
            else:
                ret = common.ERR_NOT_FOUND
                msg = "not found key for %s" % name
                break
            
            count = count + 1
        
        if ret == common.ERR_NONE:
            next_cert_pubkey = None
            next_cert_privkey = None
            # if user upload pub key, we requires 2 files, one for pub, one for priv
            if PARAM_NEXT_PUB_KEY_FILE in self.upload_files:
                if len(self.upload_files[PARAM_NEXT_PUB_KEY_FILE]) > 1:
                    next_cert = {
                        os.path.basename(self.upload_files[PARAM_NEXT_PUB_KEY_FILE][0]): [None, self.upload_files[PARAM_NEXT_PUB_KEY_FILE][0]],
                        os.path.basename(self.upload_files[PARAM_NEXT_PUB_KEY_FILE][1]): [None, self.upload_files[PARAM_NEXT_PUB_KEY_FILE][1]]
                        }
                        # pub key
                    if SB_PUB_KEY_FNAME not in next_cert or SB_PRIV_KEY_FNAME not in next_cert:
                        msg = "Not found %s or %s" (SB_PUB_KEY_FNAME, SB_PRIV_KEY_FNAME)
                        logE(msg, TAG)
                        ret = common.ERR_NOT_FOUND
                    else:
                        next_cert_pubkey = next_cert[SB_PUB_KEY_FNAME]
                        next_cert_privkey = next_cert[SB_PRIV_KEY_FNAME]
                else:
                    msg = "if upload key, request 2 file, one pub, one priv"
                    ret = common.ERR_INVALID_ARGS
                
            else: # not upload file, use key_id
                keypair_id = common.extract_form_request(request, PARAM_NEXT_PUB_KEY_FILE, default_data=None)
                if keypair_id is not None and keypair_id != common.NONE_KEY_ID:
                    key_info = keyMgr().get_key(keypair_id)
                    if key_info is not None:
                        if key_info.fids is not None and len(key_info.fids) > 0:
                            
                            # check priv key to make sure key is ok
                            # FIXME: There is a risk that key not found!
                            if SB_PUB_KEY_FNAME in key_info.fids and SB_PRIV_KEY_FNAME in key_info.fids: 
                                fid = key_info.fids[SB_PUB_KEY_FNAME]
                                fidpath = os.path.join(self.in_working_folder, SB_PUB_KEY_FNAME)
                                # FIXME: Risk of fidpath file existed????
                                ret = storageMgr().readFile(fid, fidpath)
                                if ret == common.ERR_NONE:
                                    next_cert_pubkey = [fid, fidpath]
                                    fid = key_info.fids[SB_PRIV_KEY_FNAME]
                                    fidpathpriv = os.path.join(self.in_working_folder, SB_PRIV_KEY_FNAME)
                                    # FIXME: Risk of fidpath file existed????
                                    ret = storageMgr().readFile(fid, fidpathpriv)
                                    if ret == common.ERR_NONE:
                                        next_cert_privkey = [fid, fidpath]
                                    else:
                                        msg = "readFile key for %s failed, priv fid %s not found" % (name, fid)
                                else:
                                    msg = "readFile key for %s failed, pub fid %s not found" % (name, fid)
                            else:
                                ret = common.ERR_NOT_FOUND
                                msg = "not found suitable key in %s" % keypair_id
                                if (DEBUG): logD("key_info.fids %s" % str(key_info.fids))
                        else:
                            ret = common.ERR_NOT_FOUND
                            msg = "not found any key for key %s" % keypair_id
                    else:
                        ret = common.ERR_NOT_FOUND
                        msg = "not found any key for key %s" % keypair_id
                else:
                    # let's generate key
                    log("Generate key")
                    from server.enc import generateRsaKey
                    pwd = common.extract_form_request(request, "next-cert-pubkey-pwd", default_data=None)
                    keys = generateRsaKey(
                        pwd = pwd, 
                        keydir = self.in_working_folder, 
                        privName = SB_PRIV_KEY_FNAME, 
                        pubName = SB_PUB_KEY_FNAME,
                        keysize = 2048
                        )
                    if keys is not None:
                        if (DEBUG): logD("Save priv %s " % keys[SB_PRIV_KEY_FNAME], TAG)
                        next_cert_privkey = [None, keys[SB_PRIV_KEY_FNAME]]
                        next_cert_pubkey = [None, keys[SB_PUB_KEY_FNAME]]
                    else:
                        ret = common.ERR_FAILED
                        msg = "Generate next cert key failed"

            if ret == common.ERR_NONE and next_cert_pubkey is not None and next_cert_privkey is not None:
                self.next_cert_pubkey = next_cert_pubkey
                self.next_cert_privkey = next_cert_privkey
            else:
                [ret, msg] = [ret, msg] if ret != common.ERR_NONE else [common.ERR_FAILED, "Failed"]

        from server.sign.signrenesas import RENESAS_TOOL_NAME
        self.tool = RENESAS_TOOL_NAME
        if (DEBUG): logD("next_cert_pubkey %s" % str(self.next_cert_pubkey), TAG)
        if (DEBUG): logD("next_cert_privkey %s" % str(self.next_cert_privkey), TAG)
        if (DEBUG): logD("keypair %s" % str(self.keypair), TAG)
        
        if ret == common.ERR_NONE:
            [ret, msg] = self.validate()
        
        if (DEBUG): logD("parse %d - %s" % (ret, msg), TAG)
        
        return [ret, msg]

    
    def toString(self, isFull=False):
        str = ""

        str += "\n"
        return str

   # check request info
    def validate(self):
        __result_str = ""
        [__result_code, __result_str] = super(RenesasKeyCertRequest, self).validate()

        if self.keypair is None:
            __result_code = common.ERR_INVALID_ARGS
            __result_str += "No keypair, "
        
        return [__result_code, __result_str]


SB_PRIV_KEY_FNAME = "sb_key.pem"
SB_PUB_KEY_FNAME = "sb_key_pub.pem"
SB_CERT_FNAME = "sb_key_cert.bin"
SB_CERT_FNAME2 = "out_cert_file"

REQUIRE_KEY = {
    SB_PRIV_KEY_FNAME:".",
    SB_PUB_KEY_FNAME:".",
    SB_CERT_FNAME:".",
    }

REQUIRE_KEY_DESC = {
    SB_PRIV_KEY_FNAME:"Private key",
    SB_PUB_KEY_FNAME:"Public key",
    SB_CERT_FNAME:"Certification",
}
#
# Key certificate generation tool
#
class RenesasKeyCertTool(KeyTool):
    
    def onKeyDeleted(self, key_info):
        if (DEBUG): logD("onKeyDeleted", TAG)
        # TODO: check if key is being used by other key
        return common.ERR_NONE

    def getName(self):
        return RENESAS_KEY_CERT_TOOL_NAME

    # return dic with key is file name and values is relative path (not include file)
    def get_require_keys(self):
        return REQUIRE_KEY

    def get_require_keys_desc(self):
        return REQUIRE_KEY_DESC

        # Get template render for webpage used to manual sign
    def get_html_render(self, request):
        from server.sign import signfactory as signfactory
        from server.login.login import is_login, current_username
        from server.app import getProjectList
        from server.app import getModelList
        from server.key.renesas.root_key_tool import RENESAS_ROOT_KEY_TOOL_NAME
        from server.sign.signrenesas import RENESAS_TOOL_NAME
        from server.sign.signrenesas import RENESAS_TOOL_DESC
        root_key_list = keyMgr().get_all_keys(tool=RENESAS_TOOL_NAME, keytool=RENESAS_ROOT_KEY_TOOL_NAME)
        key_cert_list = keyMgr().get_all_keys(tool=RENESAS_TOOL_NAME, keytool=RENESAS_KEY_CERT_TOOL_NAME)
        return render_template(
            "key/key_gen_cert_renesas.html"
            # common for headers
            , login=is_login(request)
            , username=current_username()
            # common for sign
            , module="Generate Key Certificate"
            , project_list=getProjectList()
            , model_list=getModelList()
            , root_key_list=root_key_list
            , key_cert_list=key_cert_list
            , default_cert_key_id=common.NONE_KEY_ID
            , toolname=RENESAS_TOOL_NAME
            , tooldesc=RENESAS_TOOL_DESC
            , modelany = common.ANY_INFO
            )

    # parse request
    def parse(self, request):
        key_req = RenesasKeyCertRequest()
        [ret, msg] = key_req.parse(request)
        # TODO: handle error case
        return [ret, key_req if ret == common.ERR_NONE else msg]

    # Generate key
    def do_generate_key(self, key_req):
        if (DEBUG): logD("do_generate_key", TAG)
        ret = common.ERR_NONE
        msg = ""
        # prepare tool dir, unzip tool to this dir
        tool_working_folder = os.path.join(key_req.out_working_folder, "tool")
        common.mkdir(tool_working_folder)
        if os.path.exists(RENESAS_SIGN_TOOL_ZIP_PATH) and common.isZipFile(RENESAS_SIGN_TOOL_ZIP_PATH):
            if (DEBUG): logD("extract tool from %s to %s" %(RENESAS_SIGN_TOOL_ZIP_PATH, tool_working_folder))
            with zipfile.ZipFile(RENESAS_SIGN_TOOL_ZIP_PATH, 'r') as zip_ref:
                zip_ref.extractall(tool_working_folder)
        else:
            logE("Tool not found", TAG)
            return [common.ERR_NOT_FOUND, "Tool not found"]

        if key_req.next_cert_pubkey is None or key_req.next_cert_privkey is None:
            logE("not nex cert key (priv or pub)", TAG)
            return [common.ERR_NOT_FOUND, "No key"]

        sign_script = os.path.join(tool_working_folder, SIGNING_TOOL_SCRIPT)
        if (DEBUG): logD("sign_script %s" % sign_script)

        if not os.path.exists(sign_script):
            logE("%s not found" % sign_script, TAG, True)
        
        import subprocess
        subprocess.call(['chmod', '-R', '0755', tool_working_folder])
        
        cfg_file = os.path.join(key_req.out_working_folder, KEY_CERT_CFG_FNAME)
        key_req.out_cert_file = os.path.join(key_req.out_working_folder, KEY_CERT_BIN_FNAME)
        key_req.hash_out = {}
        # prepare config file
        try:
            with open(cfg_file, 'wb+') as f:
                f.write(b"[KEY-CFG]\n")
                count = 1
                while count <= key_req.num_key :
                    name = "%s%d" % (PARAM_ROOT_KEY_FILE, count)
                    keyname = name if key_req.num_key > 1 else PARAM_ROOT_KEY_FILE
                    f.write(("%s = %s\n" % (keyname, key_req.keypair[name][1] if name in key_req.keypair else "")).encode())

                    keyname = '{0}{1}'.format(PARAM_ROOT_KEY_PASS, count) if key_req.num_key > 1 else PARAM_ROOT_KEY_PASS
                    f.write(("%s = %s\n" % (
                        keyname, 
                        key_req.keypair_pwd[name][1] if name in key_req.keypair_pwd and key_req.keypair_pwd[name] is not None else "")
                        ).encode())
                    keyname = '{0}{1}'.format(PARAM_HASH_OUT, count) if key_req.num_key > 1 else PARAM_HASH_OUT
                    hashoutpath = os.path.join(key_req.out_working_folder, name)
                    key_req.hash_out[name] = hashoutpath
                    f.write(("%s = %s\n" % (keyname, hashoutpath)).encode())

                    count = count + 1
                    
                f.write(("hbk-id = %d\n" % (key_req.hbkid)).encode())
                f.write(("nvcounter-id = %d\n" % (key_req.nv_counter_id)).encode())
                f.write(("nvcounter-val = %s\n" % (key_req.nv_counter_val)).encode())
                f.write(("next-cert-pubkey = %s\n" % key_req.next_cert_pubkey[1]).encode())
                f.write(("cert-pkg = %s\n" % (key_req.out_cert_file)).encode())
            if (DEBUG): logD("Write done")
        except:
            traceback.print_exc()
            if (DEBUG): logD("Write failed")

        # run script
        command = "%s %s --type=key --cfg=%s" % (
            sign_script, # sign script
            "-v" if DEBUG else "",
            cfg_file
             )

        log("Signing script: %s" % sign_script, TAG)
        if (DEBUG): logD ("command: " + str(command), TAG)

        # run signing script
        try:
            import subprocess
            child = subprocess.run(command, shell=True, timeout = COMMAND_TIMEOUT_SECOND if COMMAND_TIMEOUT_SECOND > 0 else None)
            rescmd = child.returncode

            # check result
            if (DEBUG): logD("command %s" % str(rescmd))
            if rescmd == 0 :
                if key_req.out_cert_file is not None and os.path.exists(key_req.out_cert_file):
                    ret = common.ERR_NONE
                else:
                    ret = common.ERR_FAILED
                    msg = "Signed failed, cert-pkg not found"
                    logE("Signed failed, %s not found" % (key_req.out_cert_file), TAG, True)
            else:
                logE("Signed failed with command %s, res %s" % (command, str(rescmd)), TAG, True)
            
        except:
            traceback.print_exc()
            msg = "Exception"
            ret = common.ERR_EXCEPTION

        # save to db
        if ret == common.ERR_NONE:
            files = {}
            cerinfo = RenesasKeyCertInfo()
            cerinfo.type = KEY_CERTIFICATE_TYPE
            cerinfo.nv_counter_id = key_req.nv_counter_id
            cerinfo.nv_counter_val = key_req.nv_counter_val
            for key, path in key_req.keypair.items():
                # cert-keypair
                if path[0] is not None:
                    cerinfo.keypair[key] = path[0]
                else:
                    [ret, fid] = storageMgr().writeFile(path[1], key, key_req.key_info.name)
                    if ret == common.ERR_NONE:
                        cerinfo.keypair[key] = fid
                    else:
                        break
                key_req.key_info.addFid(key, cerinfo.keypair[key])
                # cert-keypair-pwd
                if key_req.keypair_pwd[key] is not None:
                    pwd = key_req.keypair_pwd[key]
                    if pwd[0] is not None:
                        cerinfo.keypair_pwd[key] = path[0]
                    else:
                        [ret, fid] = storageMgr().writeFile(pwd[1], "%s-pass" % key, key_req.key_info.name)
                        if ret == common.ERR_NONE:
                            cerinfo.keypair_pwd[key] = fid
                        else:
                            break
                    key_req.key_info.addFid(key, cerinfo.keypair_pwd[key])
                # hasout
                # we use keyname for name of hash-out field, as each hash-out is used for each key
                [ret, fid] = storageMgr().writeFile(key_req.hash_out[key], "%s-hasout" % key, key_req.key_info.name)
                if ret == common.ERR_NONE:
                    cerinfo.hash_out[key] = fid
                    key_req.key_info.addFid(key, cerinfo.hash_out[key])
                else:
                    break
            if ret == common.ERR_NONE:
                # next-cert-pubkey
                if key_req.next_cert_pubkey[0] is not None:
                    cerinfo.next_cert_pubkey = key_req.next_cert_pubkey[0]
                else:
                    [ret, fid] = storageMgr().writeFile(key_req.next_cert_pubkey[1], "next_cert_pubkey", key_req.key_info.name)
                    if ret == common.ERR_NONE:
                        cerinfo.next_cert_pubkey = fid
                    
                if ret == common.ERR_NONE:
                    key_req.key_info.addFid(SB_PUB_KEY_FNAME, cerinfo.next_cert_pubkey, True)
            
            # private key of next-cert-pubkey
            if ret == common.ERR_NONE:
                if key_req.next_cert_privkey[0] is not None:
                    cerinfo.next_cert_privkey = key_req.next_cert_privkey[0]
                else:
                    [ret, fid] = storageMgr().writeFile(key_req.next_cert_privkey[1], "next_cert_privkey", key_req.key_info.name)
                    if ret == common.ERR_NONE:
                        cerinfo.next_cert_privkey = fid
            
            if ret == common.ERR_NONE:
                key_req.key_info.addFid(SB_PRIV_KEY_FNAME, cerinfo.next_cert_privkey)

                # cert-pkg
                [ret, fid] = storageMgr().writeFile(key_req.out_cert_file, "out_cert_file", key_req.key_info.name)
                if ret == common.ERR_NONE:
                    cerinfo.out_cert_file = fid
                    key_req.key_info.addFid(SB_CERT_FNAME, cerinfo.out_cert_file, True)

            # import key
            if ret == common.ERR_NONE:
                key_req.key_info.metadata = cerinfo.toJson()
                [ret, msg] = keyMgr().import_key(key_req.key_info, key_req.access_token, key_req.out_working_folder)

        key_req.clean()
        return [ret, msg]
