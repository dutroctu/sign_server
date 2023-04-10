#!/usr/bin/env python
#
#  IMPORT KEY
#


from flask import render_template
from server.app import DEBUG
import os
from server.applog import log
from server.applog import logE
from server.applog import logD
from server.app import getRootToolDir
from server import key as key
import traceback
from server import common as common
from server.common import ERR_INVALID_DATA



from server.key.key_mng import keyMgr
from server.key.key_tool import KeyRequest
from server.key.key_tool import KeyTool
import json
import zipfile

from server.storage.storage_mgr import storageMgr

TAG="renesaspridbgcert"

RENESAS_PRI_DBG_CERT_TOOL_NAME = "renesas_pri_dbg_cert"

# INPUT PARAMETER
PARAM_ROOT_KEY_FILE="cert-keypair" # root key
PARAM_ROOT_KEY_PASS="cert-keypair-pwd" # root key pass
PARAM_HASH_OUT="hash-out"

PARAM_NEXT_PUB_KEY_FILE="next-cert-pubkey"
PARAM_NEXT_PUB_KEY_PASS="next-cert-pubkey-pwd"

# SIGNING TOOL
RENESAS_TOOL_DIR_NAME="renesas_tools"
SIGNING_TOOL_ZIP = "dbgsigningtool.zip"
SIGNING_TOOL_SCRIPT = "sign.sh"

RENESAS_SIGN_TOOL_ZIP_PATH = os.path.join(getRootToolDir(), RENESAS_TOOL_DIR_NAME, SIGNING_TOOL_ZIP)

# CONFIGURATION NAME
KEY_CERT_CFG_FNAME = "sb_dbg_prim_cert.cfg"
KEY_CERT_BIN_FNAME = "sb_dbg_prim_cert.bin" # output binary name


COMMAND_TIMEOUT_MIN = 1
COMMAND_TIMEOUT_SECOND = (COMMAND_TIMEOUT_MIN * 60)


UNKNOWN_TYPE = 0
PRIV_DBG_CERTIFICATE_TYPE = 1 # Primary debug cert 
SEC_DBG_CERTIFICATE_TYPE = 2 # secondary debug cert


# Predefined debug mask
# WARNING: Don't remote all, as first element is used for default one in html
DEBUG_MASK_LIST = {
      "0x08000199":"CA57/53 Normal World Debugging Read/Write Enable"
    , "0x080001DD":"CA57/53 Normal World Debugging Read/Write , Secure World Debugging Read only Enable"
    , "0x080001FF":"CA57/53 Normal/Secure World Debugging Read/Write Enable"
    , "0x080007FF":"CA57/53 and CR7 Normal/Secure World Read/Write Enable"
    , "0xFFFFFFFF":"All (NOT recommended)"
}

DEFAULT_LCS=2
DEFAULT_HBK_ID=2


# FIX key name
SB_PRIV_KEY_FNAME = "sw_prv_key.pem" # private key
SB_PUB_KEY_FNAME = "sw_pub_key.pem" # public key
SB_CERT_FNAME = "sb_dbg_prim_cert.bin" # primary debug cert bin
SB_CERT_FNAME2 = "out_cert_file" # primary debug cert bin 2

# list of require key, when import key
REQUIRE_KEY = {
    SB_PRIV_KEY_FNAME:".",
    SB_PUB_KEY_FNAME:".",
    SB_CERT_FNAME:".",
    }

REQUIRE_KEY_INFO = {
    SB_PRIV_KEY_FNAME:"RSA private key, in pem format",
    SB_PUB_KEY_FNAME:"RSA public key, in pem format",
    SB_CERT_FNAME:"Primary Debug Certificate package",
    }


#######################################################################################
# Renesas common debug key info
#######################################################################################
class RenesasDbgKeyInfo:
    # common info
    type = UNKNOWN_TYPE
    keypair = {}
    keypair_pwd = {}
    debug_mask = 0
    hash_out = {}
    out_cert_file = ""
    jdata = None
    def __init__(self):
        self.keypair = {}
        self.keypair_pwd = {}
        self.hash_out = {}
        self.type = UNKNOWN_TYPE
        self.debug_mask = 0
        self.out_cert_file = ""
        self.jdata = None

    # convert to json string, return json string on success, None otherwise
    def toJsonObj(self):
        jdata = {
            "type":self.type,
            "keypair":self.keypair,
            "keypair_pwd":self.keypair_pwd,
            "debug_mask":self.debug_mask,
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
            self.debug_mask = jdata["debug_mask"] if "debug_mask" in jdata else 0
            self.keypair = jdata["keypair"] if "keypair" in jdata else {}
            self.keypair_pwd = jdata["keypair_pwd"] if "keypair_pwd" in jdata else {}

            self.out_cert_file = jdata["out_cert_file"] if "out_cert_file" in jdata else 0
            self.hash_out = jdata["hash_out"] if "hash_out" in jdata else {}
            self.jdata = jdata
            return common.ERR_NONE
        except:
            traceback.print_exc()
            logE("Meta file: Parse from json failed %s " % val, TAG)
            return common.ERR_EXCEPTION

######################################################################################
# Primary debug cert info
#######################################################################################
class RenesasPriDbgCertInfo(RenesasDbgKeyInfo):
    lcs = 0 # Lifecycle States
    hbkid = 0 # Boot Public Key
    next_cert_pubkey = ""
    next_cert_privkey = ""
    def __init__(self):
        self.lcs = 0
        self.hbkid = 0
        self.next_cert_pubkey = ""
        self.next_cert_privkey = ""

    # convert to json string, return json string on success, None otherwise
    def toJsonObj(self):
        jcommondata = super(RenesasPriDbgCertInfo, self).toJsonObj()
        jkeydata = {
            "lcs":self.lcs,
            "hbkid":self.hbkid,
            "next_cert_pubkey":self.next_cert_pubkey,
            "next_cert_privkey":self.next_cert_privkey,
            }
        jdata = {**jcommondata, **jkeydata}
        return jdata

    # parse json string, return ERR_NONE on success, error code otherwise
    def fromJson(self, val):
        super(RenesasPriDbgCertInfo, self).fromJson(val)
        try:
            jdata = self.jdata

            # parse data
            self.lcs = jdata["lcs"] if "lcs" in jdata else 0
            self.hbkid = jdata["hbkid"] if "hbkid" in jdata else 0
            self.next_cert_pubkey = jdata["next_cert_pubkey"] if "next_cert_pubkey" in jdata else 0
            self.next_cert_privkey = jdata["next_cert_privkey"] if "next_cert_privkey" in jdata else 0
            self.jdata = jdata
            return common.ERR_NONE
        except:
            traceback.print_exc()
            logE("Meta file: Parse from json failed %s " % val, TAG)
            return common.ERR_EXCEPTION

#######################################################################################
# Request to generate Primary Debug cert
#######################################################################################
class RenesasPriDbgKeyRequest(KeyRequest):
    pwd = ""
    lcs = DEFAULT_LCS
    hbkid = DEFAULT_HBK_ID
    keypair = {} # root key
    keypair_pwd = {}
    hash_out = {}
    next_cert_pubkey = None # pri debug cert key
    next_cert_privkey = None # pri debug cert key
    out_cert_file = ""
    debug_mask = 0
    type = UNKNOWN_TYPE
    def __init__(self):
        super(RenesasPriDbgKeyRequest, self).__init__()
        self.pwd = ""
        self.hbkid = 0
        self.keypair = {}
        self.keypair_pwd = {}
        self.hash_out = {}
        self.next_cert_pubkey = None
        self.next_cert_privkey = None
        self.out_cert_file = ""
        self.type = UNKNOWN_TYPE
        self.debug_mask = 0

    # parse request
    def parse(self, request):
        if (DEBUG): logD("RenesasPriDbgKeyRequest parse", TAG)
        ret = common.ERR_FAILED
        msg = ""
        [ret, msg] = super(RenesasPriDbgKeyRequest, self).parse(request)

        if ret != common.ERR_NONE:
            logE("RenesasPriDbgKeyRequest supper failed %d - %s" % (ret, msg), TAG)
            return [ret, msg]

        self.lcs = common.extract_form_request(request, "lcs_value", is_int=True, default_data=DEFAULT_LCS)
        self.hbkid = common.extract_form_request(request, "hbk_id_value", is_int=True, default_data=DEFAULT_HBK_ID)

        # read debug mask and convert to int value
        debug_mask_str = common.extract_form_request(request, "debug_mask", is_int=False, default_data=None)
        if debug_mask_str is None or len(debug_mask_str) == 0:
            logE("Invalid debug mask", TAG)
            return [common.ERR_INVALID_ARGS, "Invalid debug mask"]
        try:
            self.debug_mask = int(debug_mask_str, 0)
        except:
            traceback.print_exc()
            msg = "Invalid debug mask %s" % debug_mask_str
            logE(msg, TAG)
            return [common.ERR_INVALID_ARGS, msg]

        if (DEBUG): logD("debug_mask 0x%x" % self.debug_mask, TAG)
        if (DEBUG): logD("lcs %d" % self.lcs, TAG)
        if (DEBUG): logD("hbkid %d" % self.hbkid, TAG)

        # check target key tool
        if self.key_info.target_keytool is None:
            if (DEBUG): logD("not key tool, set default to %s" % RENESAS_PRI_DBG_CERT_TOOL_NAME, TAG)
            self.key_info.target_keytool = str([RENESAS_PRI_DBG_CERT_TOOL_NAME]) 

        if (DEBUG): logD("target_keytool %s" % str(self.key_info.target_keytool), TAG)

        # key dir
        keydir = os.path.join(self.in_working_folder, "keydir")
        common.mkdir(keydir)

        # [PRIM-DBG-CFG]
        # cert-keypair = sd_input/vf_root_key.pem
        # cert-keypair-pwd =
        # lcs = 2
        # debug-mask = 0xffffffff
        # hbk-id = 2
        # next-cert-pubkey = sd_input/sw_pub_key.pem
        # cert-pkg = sd_output/sb_dbg_prim_cert.bin 

        name = PARAM_ROOT_KEY_FILE
        keyname = PARAM_ROOT_KEY_PASS
        if (DEBUG): logD("name %s" % name, TAG)
        if (DEBUG): logD("keyname %s" % keyname, TAG)
        if (DEBUG): logD("upload_files %s" % str(self.upload_files), TAG)

        pwdpath = None
        pwd = None
        keypair = None # [fid or None, # path to file]
        keypair_pwd = None # [fid or None, # path to file]

        # Prepare root key

        # if key is uploaded, use uploaed key
        if name in self.upload_files and len(self.upload_files[name]) > 0:
            keypair = [None, self.upload_files[name][0]] # uhm, asume that upload_files contains valid path, as being checked by key_tool
            keypair_pwd = [None, common.extract_form_request(request, keyname, default_data="")]
        else: # get key using keyid in form request
            #if not upload, get key id from parameter
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
            # TODO: password?????
            # TODO: key name????


        if (DEBUG): logD("keypair %s" % str(keypair), TAG)
        if (DEBUG): logD("keypair_pwd %s" % str(keypair_pwd), TAG)

        # check root key info
        if keypair is not None and len(keypair) > 1:
            self.keypair[name] = keypair
            # copy key pwd to file
            # TODO: it's not safe, should enter key to stdin?
            if keypair_pwd is not None and len(keypair_pwd) > 1: # 2 params
                pwdpath = os.path.join(keydir, keyname)
                if common.write_string_to_file(pwdpath, keypair_pwd[1]):
                    keypair_pwd[1] = pwdpath
                    if (DEBUG): logD("pwdpath %s" % pwdpath, TAG)
                    self.keypair_pwd[name] = keypair_pwd
                else:
                    ret = common.ERR_FAIELD
                    msg = "failed to prepare pwd"

            else:
                self.keypair_pwd[name] = None
        else: # no root key specified, out
            ret = common.ERR_NOT_FOUND
            msg = "not found key for %s" % name
            
        
        # now, check primary key, key used to sign secondary debug cert
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
                # TODO: password info????

            if ret == common.ERR_NONE and next_cert_pubkey is not None and next_cert_privkey is not None:
                self.next_cert_pubkey = next_cert_pubkey
                self.next_cert_privkey = next_cert_privkey
            else:
                [ret, msg] = [ret, msg] if ret != common.ERR_NONE else [common.ERR_FAILED, "Failed"]

        # signing tool to use this key
        from server.sign.signrenesas_dbg import RENESAS_DBG_TOOL_NAME
        tool = common.extract_form_request(request, "tool", is_int=False, default_data=None)
        if tool is None:
            tool = RENESAS_DBG_TOOL_NAME
        else:
            if (tool != RENESAS_DBG_TOOL_NAME):
                ret = common.ERR_INVALID_ARGS
                msg = "Unsupported sign tool %s" % tool

        self.tool = tool

        if (DEBUG): logD("next_cert_pubkey %s" % str(self.next_cert_pubkey), TAG)
        if (DEBUG): logD("next_cert_privkey %s" % str(self.next_cert_privkey), TAG)
        if (DEBUG): logD("keypair %s" % str(self.keypair), TAG)
        
        if ret == common.ERR_NONE:
            [ret, msg] = self.validate()
        
        if (DEBUG): logD("parse %d - %s" % (ret, msg), TAG)
        
        # All done now
        return [ret, msg]

    
    def toString(self, isFull=False):
        str = ""
        str += "debug_mask: 0x%x;\n" % self.debug_mask
        str += "\n"
        return str

   # check request info
    def validate(self):
        __result_str = ""
        [__result_code, __result_str] = super(RenesasPriDbgKeyRequest, self).validate()

        if self.keypair is None:
            __result_code = common.ERR_INVALID_ARGS
            __result_str += "No keypair, "

        if self.hbkid != DEFAULT_HBK_ID: # only accept defaul value, according to renesas guide
            __result_code = common.ERR_INVALID_ARGS
            __result_str += "invalid hbk_id, "
        
        
        if self.lcs != DEFAULT_LCS: # only accept defaul value, according to renesas guide
            __result_code = common.ERR_INVALID_ARGS
            __result_str += "invalid lcs, "

        if self.debug_mask == 0:
            __result_code = common.ERR_INVALID_ARGS
            __result_str += "invalid debug_mask, "


        if self.tool is None or len(self.tool) == 0:
            __result_code = common.ERR_INVALID_ARGS
            __result_str += "No sign tool, "

        # TODO: validate key (root key, next key)

        return [__result_code, __result_str]

################################################################################################
# Key certificate generation tool
################################################################################################
class RenesasPriDbgCertTool(KeyTool):
    
    def onKeyDeleted(self, key_info):
        if (DEBUG): logD("onKeyDeleted", TAG)
        # TODO: check if key is being used by other key
        return common.ERR_NONE

    def getName(self):
        return RENESAS_PRI_DBG_CERT_TOOL_NAME

    # return dic with key is file name and values is relative path (not include file)
    def get_require_keys(self):
        return REQUIRE_KEY

    # return dic with key is file name and explanation for key
    def get_require_keys_info(self):
        return REQUIRE_KEY_INFO

    def get_require_keys_desc(self):
        return REQUIRE_KEY_INFO

    # Get template render for webpage used to manual sign
    def get_html_render(self, request):
        from server.sign import signfactory as signfactory
        from server.login.login import is_login, current_username
        from server.app import getProjectList
        from server.app import getModelList
        from server.key.renesas.root_key_tool import RENESAS_ROOT_KEY_TOOL_NAME
        from server.sign.signrenesas import RENESAS_TOOL_NAME
        from server.sign.signrenesas_dbg import RENESAS_DBG_TOOL_NAME
        from server.sign.signrenesas_dbg import RENESAS_DBG_TOOL_DESC
        # get root key, used to create priv cert pkg
        root_key_list = keyMgr().get_all_keys(tool=RENESAS_TOOL_NAME, keytool=RENESAS_ROOT_KEY_TOOL_NAME)
        # list of existing pri debug cert key
        pri_dbg_key_list = keyMgr().get_all_keys(tool=RENESAS_DBG_TOOL_NAME, keytool=RENESAS_PRI_DBG_CERT_TOOL_NAME)
        return render_template(
            "key/key_gen_pri_dbg_cert_renesas.html"
            # common for headers
            , login=is_login(request)
            , username=current_username()
            # common for sign
            , module="Generate Primary Debug Certificate"
            , project_list=getProjectList()
            , model_list=getModelList()
            , root_key_list=root_key_list # root key to be used 
            , key_list=pri_dbg_key_list # existing key to be used
            , default_cert_key_id=common.NONE_KEY_ID
            , toolname=RENESAS_DBG_TOOL_NAME # tool name that use this key
            , tooldesc=RENESAS_DBG_TOOL_DESC
            , modelany = common.ANY_INFO
            , debug_mask_map = DEBUG_MASK_LIST
            , key_title = "Root key"
            , default_debug_mask = list(DEBUG_MASK_LIST.keys())[0]
            )

    # parse request
    def parse(self, request):
        key_req = RenesasPriDbgKeyRequest()
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
        sign_script = os.path.join(tool_working_folder, SIGNING_TOOL_SCRIPT)
        if (DEBUG): logD("sign_script %s" % sign_script)

        if not os.path.exists(sign_script):
            logE("%s not found" % sign_script, TAG, True)
        

        # require next pub key
        if key_req.next_cert_pubkey is None or key_req.next_cert_privkey is None:
            logE("not next cert key (priv or pub)", TAG)
            return [common.ERR_NOT_FOUND, "No key"]

        if key_req.keypair is None or len(key_req.keypair) == 0:
            logE("not root key (priv or pub)", TAG)
            return [common.ERR_NOT_FOUND, "No root key"]

        import subprocess
        subprocess.call(['chmod', '-R', '0755', tool_working_folder])
        
        cfg_file = os.path.join(key_req.out_working_folder, KEY_CERT_CFG_FNAME)
        key_req.out_cert_file = os.path.join(key_req.out_working_folder, KEY_CERT_BIN_FNAME)
        key_req.hash_out = {}
        # prepare config file
        try:
            with open(cfg_file, 'wb+') as f:
                f.write(b"[PRIM-DBG-CFG]\n")
                name = PARAM_ROOT_KEY_FILE
                keyname = PARAM_ROOT_KEY_FILE
                f.write(("%s = %s\n" % (keyname, key_req.keypair[name][1] if name in key_req.keypair else "")).encode())

                keyname = PARAM_ROOT_KEY_PASS
                f.write(("%s = %s\n" % (
                    keyname, 
                    key_req.keypair_pwd[name][1] if name in key_req.keypair_pwd and key_req.keypair_pwd[name] is not None else "")
                    ).encode())
                keyname = PARAM_HASH_OUT
                hashoutpath = os.path.join(key_req.out_working_folder, name)
                key_req.hash_out[name] = hashoutpath
                f.write(("%s = %s\n" % (keyname, hashoutpath)).encode())

                    
                f.write(("hbk-id = %d\n" % (key_req.hbkid)).encode())
                f.write(("lcs = %d\n" % (key_req.lcs)).encode())
                f.write(("debug-mask = 0x%x\n" % (key_req.debug_mask)).encode())
                f.write(("next-cert-pubkey = %s\n" % key_req.next_cert_pubkey[1]).encode())
                f.write(("cert-pkg = %s\n" % (key_req.out_cert_file)).encode())
            if (DEBUG): logD("Write done")
        except:
            traceback.print_exc()
            if (DEBUG): logD("Write failed")

        # run script
        command = "%s %s --type=primary --cfg=%s" % (
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
            cerinfo = RenesasPriDbgCertInfo()
            cerinfo.type = PRIV_DBG_CERTIFICATE_TYPE
            cerinfo.debug_mask = key_req.debug_mask
            cerinfo.lcs = key_req.lcs
            cerinfo.hbkid = key_req.hbkid
            for key, path in key_req.keypair.items():
                # uhm, we try to backup root key by ourselves, for the case that root key is delete....
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

        # ALL done, clean key data
        key_req.clean()
        return [ret, msg]

    # return array with 2 element: result of check, and string of checking message
    def check_key(self, keyid, isdetail=False):
        ret = common.ERR_NOT_SUPPORT
        msg = "FAILED"
        if (DEBUG): logD("check_key %s" % keyid)
        keyinfo = keyMgr().get_key(keyid)
        if (keyinfo is not None):
            msg = "Check key id: %s;\n" % keyid
            from server.database.key import KEY_STATUS_READY
            if (keyinfo.status == KEY_STATUS_READY):
                if keyinfo.metadata is not None and len(keyinfo.metadata) > 0:
                    cerinfo = RenesasPriDbgCertInfo()
                    ret = cerinfo.fromJson(keyinfo.metadata)
                else:
                    ret = ERR_INVALID_DATA

                if ret == common.ERR_NONE:
                    msg += "Type: %d;\n" % (cerinfo.type)
                    msg += "Debug mask: 0x%x;\n" % (cerinfo.debug_mask)
                    msg += "LCS: %d;\n" % (cerinfo.lcs)
                    msg += "hbkid: %d;\n" % (cerinfo.hbkid)
                    msg += "next_cert_pubkey: %s;\n" % (cerinfo.next_cert_pubkey if cerinfo.next_cert_pubkey is not None else "No")
                    msg += "out_cert_file: %s;\n" % (cerinfo.out_cert_file if cerinfo.out_cert_file is not None else "No")
                    msg += "hash_out: %s;\n" % (str(cerinfo.hash_out) if cerinfo.hash_out is not None else "No")
                    if isdetail:
                        msg += "keypair: %s;\n" % (str(cerinfo.keypair) if cerinfo.keypair is not None else "No")
                        msg += "keypair_pwd: %s;\n" % (str(cerinfo.keypair_pwd) if cerinfo.keypair_pwd is not None else "No")
                    # TODO: validate file, key if they exists and valid
                else:
                    msg += "Cert info: INVALID (%d);\n" % ret
            else:
                ret = common.ERR_NOT_READY
                msg += "Key Status not ready %d;\n" % keyinfo.status
        else:
            logE("not found key %s" % (keyid), TAG, True)
            ret = common.ERR_NOT_FOUND
            msg = "Not found key %s" % keyid

        return [ret, msg]