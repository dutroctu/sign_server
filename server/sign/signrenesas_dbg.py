#!/usr/bin/env python
#
#  Generate Renesas Secondary Debug Certification
#
from flask import render_template
# import app
from server import common as common
from server.app import DEBUG

import os
from server import applog as applog 
from server.applog import log
from server.applog import logD
from server.applog import logE

from server.sign.signreq import SignRequest
from server.sign.signreq import SignTool

from server import common as common
from server.common import DEFAULT as DEFAULT
from server import hash as hash
from server.app import getProjectList
from server.app import getModelList
from server.sign.signresp import SignResp

import zipfile
import shutil
from server.login.login import is_login, current_username
import traceback
from server.sign import signfactory as signfactory

from server.key.renesas import pri_dbg_cert_tool
from server.key.renesas.pri_dbg_cert_tool import RENESAS_PRI_DBG_CERT_TOOL_NAME
from server.key.renesas.pri_dbg_cert_tool import RENESAS_SIGN_TOOL_ZIP_PATH
from server.key.renesas.pri_dbg_cert_tool import SIGNING_TOOL_SCRIPT
from server.key.renesas.pri_dbg_cert_tool import DEBUG_MASK_LIST


from server.common import INVALID_KEY_ID

TAG = "signrenesasdbg"
RENESAS_DBG_TOOL_NAME = "renesasdbg"
RENESAS_DBG_TOOL_DESC = "Renesas - Secondary Debug certification"

# command timeout, to avoid locking server (i.e. key need password, but no password is set)
# COMMAND_TIMEOUT_SECOND=300
COMMAND_TIMEOUT_MIN=30
COMMAND_TIMEOUT_SECOND=(COMMAND_TIMEOUT_MIN*60)

INPUT_IMAGE_IND_TAG = "socid"
# SIGN SCRIPT
TOOL_SIGNER_SCRIPT_FNAME="sign.sh"

PARAM_PRI_DEBG_CERT_FILE="prim-dbg-cert-pkg"


SEC_DBG_CERT_CFG_FNAME = "sb_dbg_sec_cert.cfg"
SEC_DBG_CERT_BIN_FNAME = "sb_dbg_sec_cert.bin"
SEC_DBG_HASH_OUT_FNAME = "hashout.bin"

PARAM_SOCID_VAL = "socid_val"

######################################################################################################
# Secondary Debug Certificate Request
#####################################################################################################
class SignRequestRenesasDbg(SignRequest):
    debug_mask = 0
    keypair = "" # primary debug key cert
    keypair_pwd = ""
    hash_out = {}
    out_cert_file = ""
    key_id = None
    key_info = None
    socid_val = None
    key_dir = None
    def __init__(self, request):
        if (DEBUG): logD("SignRequestRenesasDbg init", TAG)
        super(SignRequestRenesasDbg, self).__init__(request, RENESAS_DBG_TOOL_NAME)
        self.debug_mask = 0
        self.keypair = ""
        self.keypair_pwd = ""
        self.socid_val = None
        self.hash_out = {}
        self.out_cert_file = ""
        self.key_id = None
        self.key_info = None
        self.key_dir = None

        # PARSE debug mask
        debug_mask_str = common.extract_form_request(request, "debug_mask", is_int=False, default_data=None)
        if debug_mask_str is None or len(debug_mask_str) == 0:
            logE("Invalid debug mask", TAG)
            raise ValueError("Invalid debug mask")
        try:
            self.debug_mask = int(debug_mask_str, 0)
        except:
            traceback.print_exc()
            msg = "Invalid debug mask %s" % debug_mask_str
            logE(msg, TAG)
            raise ValueError(msg)

        if (DEBUG): logD("debug_mask 0x%x" % self.debug_mask, TAG)


        # parset soc id info.
        socid_str = common.extract_form_request(request, PARAM_SOCID_VAL, default_data=None)
        if (socid_str is not None) and len(socid_str) > 0:
            try:
                self.socid_val = bytearray.fromhex(socid_str)
            except:
                traceback.print_exc()
                raise ValueError("parsing socid string failed")
            
            if self.socid_val is None:
                raise ValueError("socid string invalid")
        else:
            self.socid_val = None

        if (DEBUG): logD("get key info", TAG)
        [self.key_id, self.key_info] = self.getKeyInfo(request, "key_id", "key_name", RENESAS_PRI_DBG_CERT_TOOL_NAME)
        
        if (DEBUG): logD("key id '%s'" % self.key_id, TAG)

    
    def toString(self, isFull=False):
        str = ""

        str += "\n"
        return str

    # return dic of keyinfo, with key is keytype, value is key_info
    def getListKeyInfo(self):
        return {
            "key_info":self.key_info,
            }

######################################################################################################
# Secondary Debug Certificate Tool
#####################################################################################################
class SignRenesasDbg(SignTool):

    def getName(self, desc=False):
        return RENESAS_DBG_TOOL_NAME if not desc else RENESAS_DBG_TOOL_DESC

    def parse_request(self, request):
        if (DEBUG): logD("SignRenesas parse_request")
        signreq = None
        try:
            signreq = SignRequestRenesasDbg(request)
        except Exception as e:
            traceback.print_exc()
            logE("parse_request exception %s" % str(e))
            signreq = None

        return signreq

    def check(self, __req):
        [__code, __msg] = super(SignRenesasDbg, self).check(__req)

        if (__code != 0):
            return [__code, __msg]

        __result_str = ""
        __result_code = 0

        if __req.key_id is None and __req.key_info is None:
            __result_code = -1
            __result_str += "No valid key_id or key_name"

        if __result_code == 0 and __req.key_id == INVALID_KEY_ID:
            __result_code = -1
            __result_str += "invalid/not exist key_id/name"

        if __req.socid_val is not None and len(__req.socid_val) != 32:
            __result_code = -1
            __result_str += "invalid socid, must be 32 bytes"

        if __req.debug_mask == 0:
            __result_code = common.ERR_INVALID_ARGS
            __result_str += "invalid debug_mask, "


        if (__result_code == 0):
            __result_str = "OK"

        return [__result_code, __result_str]

    # Sign target file
    def sign_target(self, __req):

        ret = common.ERR_NONE
        msg = None
        log("sign_target, uuid %s" % str(__req.session.uuid), TAG)
        # get script to sign
        if not os.path.exists(__req.tool_working_folder):
            logE("%s not found" % __req.tool_working_folder, TAG, True)
            return SignResp(__req, -1, "Not found tool to sign")

        if __req.key_dir is None or not os.path.exists(__req.key_dir):
            logE("not found keydir", TAG, True)
            return SignResp(__req, -1, "not found keydir")
        

        sign_script = os.path.join(__req.tool_working_folder, SIGNING_TOOL_SCRIPT)
        if (DEBUG): logD("sign_script %s" % sign_script)

        signed_image_folder = os.path.join(__req.tool_working_folder, "signed")
        common.mkdir(signed_image_folder)
            
        # prepare key
        log("Prepare keys", TAG)
        from server.key.renesas.pri_dbg_cert_tool import SB_PRIV_KEY_FNAME
        from server.key.renesas.pri_dbg_cert_tool import SB_PRIV_KEY_FNAME
        from server.key.renesas.pri_dbg_cert_tool import SB_CERT_FNAME
        from server.key.renesas.pri_dbg_cert_tool import SB_CERT_FNAME2
        privKey = os.path.join(__req.key_dir, SB_PRIV_KEY_FNAME)
        privKeypwd = ""
        privKeyRel = os.path.relpath(privKey, __req.tool_working_folder)
        privKeypwdRel = ""

        
        priKeyCert = os.path.join(__req.key_dir, SB_CERT_FNAME)
        priKeyCertRel = os.path.relpath(priKeyCert, __req.tool_working_folder)

        if not os.path.exists(privKey):
            logE("not found private key", TAG)
            return SignResp(__req, -1, "Not found key %s" % SB_PRIV_KEY_FNAME)
        


        if __req.key_info is not None and __req.key_info.pwd is not None and len(__req.key_info.pwd ) > 0:
            privKeypwd = os.path.join(__req.key_dir, "pwd")
            fret = common.write_string_to_file(privKeypwd, __req.key_info.pwd)
            privKeypwdRel = os.path.relpath(privKeypwd, __req.tool_working_folder)
            if not fret:
                logE("prepare pwd failed", TAG)
                return SignResp(__req, -1, "prepare pwd failed")
        
        if (DEBUG): logD("file_path_list %s" % str(__req.file_path_list), TAG)

        UPLOAD_BINARIES="uploaded_bin"
        
        # uploaded binaries folder
        uploaded_bin_dir = os.path.join(__req.tool_working_folder, UPLOAD_BINARIES)
        common.mkdir(uploaded_bin_dir)
        if (DEBUG): logD("uploaded_bin_dir %s" % uploaded_bin_dir, TAG)


        # prepare uploaded binaries
        log("Prepare binaries", TAG)
        if INPUT_IMAGE_IND_TAG in __req.file_path_list:
            files = __req.file_path_list[INPUT_IMAGE_IND_TAG]
            for file in files:
                if file is not None and len(file) > 0 and os.path.exists(file):
                    if common.isZipFile(file):
                        if (DEBUG): logD("extract zip from %s to %s" %(file, uploaded_bin_dir), TAG)
                        with zipfile.ZipFile(file, 'r') as zip_ref:
                            zip_ref.extractall(uploaded_bin_dir)
                    else:
                        shutil.copy(file, uploaded_bin_dir)
        else:
            logE("not found any binaries", TAG)
            # make table files
            if __req.socid_val is not None: # already check if len is 0, set to null, when parsing request
                socid_file = os.path.join(uploaded_bin_dir, "%s.bin" % INPUT_IMAGE_IND_TAG)
                with open(socid_file, "wb") as f:
                    f.write(__req.socid_val)
                

        # check for each program address file
        log("Scan for each socid files", TAG)
        found = 0
        for fname in os.listdir(uploaded_bin_dir):
            socid_file = os.path.join(uploaded_bin_dir, fname)
            socid_file_to_signed = os.path.join(uploaded_bin_dir, fname)
            if (DEBUG): logD("tbl_file %s" % socid_file, TAG)

            if not os.path.isfile(socid_file):
                continue


            cfg_file = os.path.join(signed_image_folder, SEC_DBG_CERT_CFG_FNAME)

            socid_file_rel = os.path.relpath(socid_file_to_signed, __req.tool_working_folder)
            socidname, _ = os.path.splitext(fname)


            has_out_file = os.path.join(signed_image_folder, "%s.hash" % socidname)
            has_out_file_rel = os.path.relpath(has_out_file, __req.tool_working_folder)

            
            out_cert_fname="%s_cert.bin" % socidname
            out_cert_file = os.path.join(signed_image_folder, out_cert_fname)
            out_cert_file_rel = os.path.relpath(out_cert_file, __req.tool_working_folder)

            try:
                with open(cfg_file, 'wb+') as f:
                    f.write(b"[SCND-DBG-CFG]\n")

                    f.write(("%s = %s\n" % (pri_dbg_cert_tool.PARAM_ROOT_KEY_FILE, privKeyRel)).encode())
                    f.write(("%s = %s\n" % (pri_dbg_cert_tool.PARAM_ROOT_KEY_PASS, privKeypwdRel)).encode())
                    f.write(("%s = %s\n" % (PARAM_PRI_DEBG_CERT_FILE, priKeyCertRel)).encode())
                     
                    f.write(("soc-id = %s\n" % socid_file_rel).encode())
                    f.write(("debug-mask = 0x%x\n" % (__req.debug_mask)).encode())
                    f.write(("%s = %s\n" % (pri_dbg_cert_tool.PARAM_HASH_OUT, has_out_file_rel)).encode())
                    f.write(("cert-pkg = %s\n" % (out_cert_file_rel)).encode())
                if (DEBUG): logD("Write done")
            except:
                traceback.print_exc()
                if (DEBUG): logD("Write failed")
                return SignResp(__req, -1, "write cfg failed")
            
            command = "%s %s --type=secondary --cfg=%s" % (
                sign_script, # sign script
                "-v" if DEBUG else "",
                cfg_file
                )
            
            log("Signing script: %s" % sign_script, TAG)
            if (DEBUG): logD ("command: " + str(command), TAG)

            res = 0

            # run signing script
            try:
                import subprocess
                child = subprocess.run(command, shell=True, timeout=COMMAND_TIMEOUT_SECOND if COMMAND_TIMEOUT_SECOND > 0 else None)
                res = child.returncode
            except:
                traceback.print_exc()
                return SignResp(__req, -1, "Sign failed, exception occurs")

            # check result
            if (DEBUG): logD("command %s" % str(res))
            if res != 0 :
                logE("Generate secondary debug cert failed with command %s, res %s" % (command, str(res)), TAG, True)
                return SignResp(__req, -1, "Generate secondary debug cert failed %s" % str(res))

            found += 1

        if (ret != common.ERR_NONE):
            return SignResp(__req, ret, msg)
        else:
            if found > 0:
                # copy public key info
                key = os.path.join(__req.key_dir, SB_CERT_FNAME)
                if os.path.exists(key):
                    if (DEBUG): logD("copy %s to %s" % (key, signed_image_folder), TAG)
                    shutil.copy(key, signed_image_folder)
                else:
                    key = os.path.join(__req.key_dir, SB_CERT_FNAME2)
                    if os.path.exists(key):
                        pubkey = os.path.join(signed_image_folder, SB_CERT_FNAME)
                        if (DEBUG): logD("copy %s to %s" % (key, pubkey), TAG)
                        shutil.copy(key, pubkey)
                
                log("Copy uploaded files to outdir", TAG)
                org_bin_dir = os.path.join(signed_image_folder, UPLOAD_BINARIES)
                common.mkdir(org_bin_dir)
                for _fname in os.listdir(uploaded_bin_dir):
                    bin_file = os.path.join(uploaded_bin_dir, _fname)
                    shutil.copy(bin_file, org_bin_dir)
                
                resp = self.packOutput(__req, signed_image_folder)
            else:
                logE("Not sign any file", TAG)
                resp = SignResp(__req, common.ERR_NOT_FOUND, "Not file to sign")

        return resp

    # do signing
    def do_sign(self, __req):
        if (DEBUG): logD("Renesas do_sign", TAG)
        # check/prepare tool
        log("Prepare tool", TAG)
        [__code, __msg] = self.prepareTool(__req, RENESAS_SIGN_TOOL_ZIP_PATH)

        if (__code != common.ERR_NONE):
            return SignResp(__req, __code, __msg)

        # Get key basing on key id, or use default one
        log ("Sign with key: %s" % __req.key_id, TAG, True)

                    
        __req.key_dir = os.path.join(__req.tool_working_folder, "key")

        if (__req.key_info != None):
            if os.path.exists(__req.key_dir):
                if (DEBUG): logD("Remove existing one to create new one")
                common.rmdirs(__req.key_dir)
            common.mkdir(__req.key_dir)
            [__code, __msg] = self.prepareKey(__req, __req.key_info, __req.key_dir)
        else:
            if not os.path.exists(__req.key_dir):
                return SignResp(__req, common.ERR_NOT_FOUND, "not found any key")
            else:
                log("do_sign, use default key", TAG)
        
        if (__code != common.ERR_NONE):
            applog.logE("Prepare key failed %d" % __code)
            return SignResp(__req, __code, __msg)
       
        return self.sign_target(__req)


    # Get template render for webpage used to manual sign
    def get_html_render_for_manual_sign(self, request):
        from server.key.key_mng import keyMgr
        from server.sign import signfactory as signfactory
        key_list = keyMgr().get_all_keys(tool=RENESAS_DBG_TOOL_NAME, keytool=RENESAS_PRI_DBG_CERT_TOOL_NAME)
        
        return render_template(
            "sign/sign_renesas_dbg.html"
            # common for headers
            , login=is_login(request)
            , username=current_username()
            # common for sign
            , module="Renesas: Generate Secondary Debug Certificate"
            , project_list=getProjectList()
            , model_list=getModelList()
            , key_list=key_list
            , default_key_id=common.DEFAULT_KEY_ID
            , toolname=RENESAS_DBG_TOOL_NAME
            , keytoolname=RENESAS_PRI_DBG_CERT_TOOL_NAME
            , debug_mask_map = DEBUG_MASK_LIST
            , key_title = "Primary debug key"
            , default_debug_mask = list(DEBUG_MASK_LIST.keys())[0]
            )


    def getKeyToolList(self):
        return [RENESAS_PRI_DBG_CERT_TOOL_NAME]