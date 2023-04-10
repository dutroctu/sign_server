#!/usr/bin/env python
#
#  SIGN FOT TBOX
#
from flask import Flask
from flask_restful import Api, Resource, reqparse
from flask import send_file
from flask import render_template
from flask import request, abort, jsonify, send_from_directory
# import app
from server import common as common
from server.app import app
from server.app import DEBUG

import os
from server import applog as applog 
from server.applog import log
from server.applog import logD
from server.applog import logE
from datetime import datetime

from server.sign.signreq import SignRequest
from server.sign.signreq import SignTool

from server import common as common
from server.common import DEFAULT as DEFAULT
from server import hash as hash
from server.app import getProjectList
from server.app import getModelList
from server.sign.signresp import SignResp
import server.sign.signfactory
import server.login.session

import zipfile
from io import BytesIO
import shutil
import subprocess
from server.login.login import is_login, current_username
import traceback
import sys
from server.app import ROOT_DIR

from server.sign import signfactory as signfactory

# from server.key.key_mng import keyMgr
from server.storage import storageMgr
from server.key.renesas import key_cert_tool
from server.key.renesas.key_cert_tool import RENESAS_KEY_CERT_TOOL_NAME
from server.key.renesas.key_cert_tool import RENESAS_SIGN_TOOL_ZIP_PATH
from server.key.renesas.key_cert_tool import SIGNING_TOOL_SCRIPT

from server.key.renesas.sb_key_tool import RENESAS_SB_KEY_TOOL_NAME

from server.key.renesas.root_key_tool import RENESAS_ROOT_KEY_TOOL_NAME
from server.key.renesas.root_key_tool import ROOT_AES_KEY_FNAME
from server.sign.renesas_ic_param import DEFAULT_ADJUST_VMA
from server.sign.renesas_ic_param import ENCRYPTION_MODE_DISABLE
from server.sign.renesas_ic_param import ENCRYPTION_MODE_ENABLE_NO_IV
from server.sign.renesas_ic_param import ENCRYPTION_MODE_ENABLE_WITH_IV

from server.common import INVALID_KEY_ID

TAG = "signrenesas"
RENESAS_TOOL_NAME = "renesas"
RENESAS_TOOL_DESC = "Renesas - Content certification"

# command timeout, to avoid locking server (i.e. key need password, but no password is set)
# COMMAND_TIMEOUT_SECOND=300
COMMAND_TIMEOUT_MIN=30
COMMAND_TIMEOUT_SECOND=(COMMAND_TIMEOUT_MIN*60)

INPUT_IMAGE_IND_TAG = "image"
INPUT_IMAGE_IND_TBL_TAG = "image_tbl"
INPUT_IMAGE_IND_MEM_TAG = "image_mem"
INPUT_IMAGE_IND_FLASH_TAG = "image_flash"
# SIGN SCRIPT
TOOL_SIGNER_SCRIPT_FNAME="sign.sh"

CONVERT_SCRIPT="srec2bin.sh"

TOOL_ANDROID_TOOL_FOLDER = os.path.join(ROOT_DIR, "tool/android_tools")

TOOL_TBOX_SECTOOL_ZIP = os.path.join(ROOT_DIR, "tool/tbox/sectool.zip")


CONTENT_CERT_CFG_FNAME = "sb_cnt_cert.cfg"
CONTENT_CERT_BIN_FNAME = "sb_cnt_cert.bin"
CONTENT_HAST_OUT_FNAME = "hashout.bin"

PARAM_INCLUDE_IN_BIN = "include_in_bin"

class SignRequestRenesas(SignRequest):
    nv_counter_id = 0
    nv_counter_val = 0
    keypair = ""
    keypair_pwd = ""
    aes_enc_key = ""
    images_table = ""
    aes_iv_get = ""
    hash_out = {}
    out_cert_file = ""
    key_id = None
    key_info = None
    root_key_id = None
    root_key_info = None
    image_ind_no = 0
    image_tbl = None
    key_dir = None
    encryption_mode = ENCRYPTION_MODE_DISABLE # 1: disable, 2: enable but not output iv, 3: enable and output iv
    include_in_bin = False # should include uploaded binaries in output or not
    adjust_vma = DEFAULT_ADJUST_VMA # vma need to convert bin to srec for content cert
    def __init__(self, request):
        if (DEBUG): logD("SignRequestRenesas init", TAG)
        super(SignRequestRenesas, self).__init__(request, RENESAS_TOOL_NAME)
        self.nv_counter_id = 0
        self.nv_counter_val = 0
        self.keypair = ""
        self.keypair_pwd = ""
        self.aes_enc_key = ""
        self.images_table = ""
        self.aes_iv_get = ""
        self.hash_out = {}
        self.out_cert_file = ""
        self.key_id = None
        self.key_info = None
        self.key_dir = None
        self.encryption_mode = 1


        self.nv_counter_id = common.extract_form_request(request, key_cert_tool.PARAM_NV_COUNTER_ID, is_int=True, default_data=0)
        self.nv_counter_val = common.extract_form_request(request, key_cert_tool.PARAM_NV_COUNTER_VAL, is_int=True, default_data=0)
        self.encryption_mode = common.extract_form_request(request, "encryption_mode", is_int=True, default_data=ENCRYPTION_MODE_DISABLE)

        memaddr = common.extract_form_request(request, INPUT_IMAGE_IND_MEM_TAG, default_data="")
        flashaddr = common.extract_form_request(request, INPUT_IMAGE_IND_FLASH_TAG, default_data="")
        if flashaddr is None or len(flashaddr) == 0:
            flashaddr = memaddr
        if memaddr is not None and len(memaddr) > 0:
            self.image_tbl = "%s %s" % (memaddr, flashaddr)

        if (DEBUG): logD("get key info", TAG)
        [self.key_id, self.key_info] = self.getKeyInfo(request, "key_id", "key_name", RENESAS_KEY_CERT_TOOL_NAME)
        [self.root_key_id, self.root_key_info] = self.getKeyInfo(request, "root_key_id", "root_key_name", RENESAS_ROOT_KEY_TOOL_NAME)
        if (DEBUG): logD("key id '%s'" % self.key_id, TAG)

        # check if need to include input binaries to output
        self.include_in_bin = common.isRequestSelected(request.form.get(PARAM_INCLUDE_IN_BIN) if PARAM_INCLUDE_IN_BIN in request.form else False)
        self.adjust_vma = common.extract_form_request(request, "adjust_vma", is_int=False, default_data=DEFAULT_ADJUST_VMA)

    
    def toString(self, isFull=False):
        str = ""

        str += "\n"
        return str

    # return dic of keyinfo, with key is keytype, value is key_info
    def getListKeyInfo(self):
        return {
            "key_info":self.key_info,
            "root_key_info":self.root_key_info
            }


class SignRenesas(SignTool):

    def getName(self, desc=False):
        return RENESAS_TOOL_NAME if not desc else RENESAS_TOOL_DESC

    def parse_request(self, request):
        if (DEBUG): logD("SignRenesas parse_request")
        return SignRequestRenesas(request)

    def check(self, __req):
        [__code, __msg] = super(SignRenesas, self).check(__req)

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

        # if "image_zip" in __req.file_path_list and "image_ind1" in __req.file_path_list:
        #     __result_code = -1
        #     __result_str += "Only file zip of list of file only, not support both"


        if __req.encryption_mode < ENCRYPTION_MODE_DISABLE or __req.encryption_mode > ENCRYPTION_MODE_ENABLE_WITH_IV:
            __result_code = -1
            __result_str += "invalid encryption_mode %d" % __req.encryption_mode

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

        # bin vs srec convert script
        bin_connvert_script = os.path.join(__req.tool_working_folder, CONVERT_SCRIPT)
        if (DEBUG): logD("bin_connvert_script %s" % bin_connvert_script)
        if not os.path.exists(bin_connvert_script):
            msg = "bin_connvert_script not found %s" % CONVERT_SCRIPT
            logE(msg, TAG, True)
            return SignResp(__req, common.ERR_NOT_FOUND, msg)
            
        # prepare key
        log("Prepare keys", TAG)
        from server.key.renesas.sb_key_tool import SB_PRIV_KEY_FNAME
        privKey = os.path.join(__req.key_dir, SB_PRIV_KEY_FNAME)
        privKeypwd = ""
        privKeyRel = os.path.relpath(privKey, __req.tool_working_folder)
        privKeypwdRel = ""
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
        
        aesKey = None
        aesKeyRel = None
        if __req.root_key_info is not None and __req.encryption_mode > ENCRYPTION_MODE_DISABLE:
            aesKey = os.path.join(__req.key_dir, ROOT_AES_KEY_FNAME)
            if not os.path.exists(aesKey):
                logE("prepare encryption key failed", TAG)
                return SignResp(__req, -1, "prepare encryption key failed")
            aesKeyRel = os.path.relpath(aesKey, __req.tool_working_folder)

        if (DEBUG): logD("file_path_list %s" % str(__req.file_path_list), TAG)

        IN_BINARY_NAME="binaries"
        UPLOAD_BINARIES="uploaded_bin"
        IN_TBL_NAME="in_tbl"

        # Prepare files
        input_bin_dir = os.path.join(__req.tool_working_folder, IN_BINARY_NAME)
        common.mkdir(input_bin_dir)
        if (DEBUG): logD("input_bin_dir %s" % input_bin_dir, TAG)

        
        # uploaded binaries folder
        uploaded_bin_dir = os.path.join(__req.tool_working_folder, UPLOAD_BINARIES)
        common.mkdir(uploaded_bin_dir)
        if (DEBUG): logD("uploaded_bin_dir %s" % uploaded_bin_dir, TAG)

        input_tbl_dir = os.path.join(__req.tool_working_folder, IN_TBL_NAME)
        common.mkdir(input_tbl_dir)
        if (DEBUG): logD("input_tbl_dir %s" % input_tbl_dir, TAG)

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
            return SignResp(__req, common.ERR_NOT_FOUND, "Not bin file to sign")

        # copy uploaded binaries to working dir
        # convert srec to bin if file is srec
        for fname in os.listdir(uploaded_bin_dir): 
            name, ext = os.path.splitext(fname)
            file = os.path.join(uploaded_bin_dir, fname)
            if ext in common.SREC_EXT: # convert from srec to bin
                binfile = os.path.join(input_bin_dir, "%s.bin" % fname)
                command = "%s %s --input=%s --output=%s --target=bin" % (
                    bin_connvert_script, # sign script
                    "-v" if DEBUG else "",
                    file,
                    binfile
                )
                log("Convert %s to bin" % fname, TAG)
                if (DEBUG): logD("command %s" % command, TAG)
                ret = common.runCommand(command)
                if (ret != common.ERR_NONE):
                    msg = "Convert %s to bin failed" % fname
                    logE(msg, TAG)
                    return SignResp(__req, ret, msg)
            else:
                shutil.copy(file, input_bin_dir) # no need to convert

        # add padding if binary is not multiple of 16 bytes (RENESAS' requirement)
        for fname in os.listdir(input_bin_dir): 
            name, ext = os.path.splitext(fname)
            file = os.path.join(input_bin_dir, fname)
            sz = os.path.getsize(file)
            mod = sz % 16
            if (DEBUG): logD("padding file %s, sz %d" % (file, sz), TAG)
            if mod != 0:
                log("Add PADDING for %s, mod %d" % (fname, mod), TAG)
                padded = [0] * (16 - mod)
                try:
                    with open(file, "ab") as f:
                        f.write(bytearray(padded))
                except:
                    traceback.print_exc()
                    logE("padding file %s failed" % file, TAG)
                    return SignResp(__req, common.ERR_FAILED, "padding file %s failed" % fname)
            else:
                log("%s Already padded, keep it as it's" % (fname), TAG)

        # program address files
        log("Prepare program address files (tbl)", TAG)
        if INPUT_IMAGE_IND_TBL_TAG in __req.file_path_list:
            files = __req.file_path_list[INPUT_IMAGE_IND_TBL_TAG]
            for file in files:
                if file is not None and len(file) > 0 and os.path.exists(file):
                    if common.isZipFile(file):
                        if (DEBUG): logD("extract zip from %s to %s" %(file, input_tbl_dir), TAG)
                        with zipfile.ZipFile(file, 'r') as zip_ref:
                            zip_ref.extractall(input_tbl_dir)
                    else:
                        shutil.copy(file, input_tbl_dir)

        # make table files
        if __req.image_tbl is not None:
            tbl_file = os.path.join(input_tbl_dir, "%s.tbl" % INPUT_IMAGE_IND_TAG)
            if os.path.exists(tbl_file):
                count=0
                while count < 1000:
                    tbl_file = os.path.join(input_tbl_dir, "%s%d.tbl" % (INPUT_IMAGE_IND_TAG,count))
                    if not os.path.exists(tbl_file):
                        break
                    count += 1
            if os.path.exists(tbl_file):
                return SignResp(__req, common.ERR_FAILED, "Cannot prepare tbl file")
            for fname in os.listdir(input_bin_dir):
                with open(tbl_file, "w") as f:
                    f.write("%s %s\n" % (fname, __req.image_tbl))

        memory_map_dict = {}
        # check for each program address file
        log("Scan for each table files", TAG)
        found = 0
        for fname in os.listdir(input_tbl_dir):
            tbl_file = os.path.join(input_tbl_dir, fname)
            tbl_file_to_signed = os.path.join(signed_image_folder, fname)
            if (DEBUG): logD("tbl_file %s" % tbl_file, TAG)

            if not os.path.isfile(tbl_file):
                continue

            # read table
            try:
                with open(tbl_file) as f:
                    content = f.readlines()
            except:
                traceback.print_exc()
                logE("parse program table file failed", TAG)
                return SignResp(__req, common.ERR_FAILED, "parse program table file failed")
            content = [x.strip() for x in content] 

            # rewrite for new path
            with open(tbl_file_to_signed, "w") as f:
                for line in content:
                    # f.write("%s/%s\n" % (IN_BINARY_NAME, line))
                    __split = line.split(" ")
                    items = []
                    if __split is not None and len(__split) > 2:
                        # try to remove redundant space in tbl file
                        for item in __split:
                            item = item.strip()
                            if len(item) > 0:
                                items.append(item)

                        if len(items) > 2:
                            _fname = items[0]
                            _name, _ext = os.path.splitext(_fname)
                            if _ext in common.SREC_EXT:
                                _name = items[0].strip()
                                _ext = ".bin"
                                _fname = _name + _ext  # we converted srec to bin before
                            f.write("%s/%s %s %s\n" % (IN_BINARY_NAME, _fname, items[1], items[2]))

                            # memory map, used to generate srec
                            memory_map_dict[_fname] = [items[1], items[2]]
                            if __req.encryption_mode > ENCRYPTION_MODE_DISABLE:
                                memory_map_dict[_name + "_enc" + _ext] = [items[1], items[2]] # renesas tool will output encrypted file to _enc
                                if __req.encryption_mode == ENCRYPTION_MODE_ENABLE_WITH_IV:
                                    memory_map_dict[_name + "_iv" + _ext] = [items[1], items[2]] # renesas tool will output iv file to _enc

            cfg_file = os.path.join(signed_image_folder, CONTENT_CERT_CFG_FNAME)

            tbl_file_rel = os.path.relpath(tbl_file_to_signed, __req.tool_working_folder)
            tblfname = os.path.basename(tbl_file_to_signed)
            tblname, _ = os.path.splitext(tblfname)


            has_out_file = os.path.join(signed_image_folder, "%s.hash" % tblname)
            has_out_file_rel = os.path.relpath(has_out_file, __req.tool_working_folder)

            
            out_cert_fname="%s.cert" % tblname
            out_cert_file = os.path.join(signed_image_folder, out_cert_fname)
            out_cert_file_rel = os.path.relpath(out_cert_file, __req.tool_working_folder)

            try:
                with open(cfg_file, 'wb+') as f:
                    f.write(b"[CNT-CFG]\n")

                    f.write(("%s = %s\n" % (key_cert_tool.PARAM_ROOT_KEY_FILE, privKeyRel)).encode())
                    f.write(("%s = %s\n" % (key_cert_tool.PARAM_ROOT_KEY_PASS, privKeypwdRel)).encode())
                    if aesKeyRel is not None:
                        f.write(("%s = %s\n" % (key_cert_tool.PARAM_AES_ENC_KEY, aesKeyRel)).encode())
                    
                    f.write(("%s = %s\n" % (key_cert_tool.PARAM_AES_IV_GET, "yes" if __req.encryption_mode == ENCRYPTION_MODE_ENABLE_WITH_IV else "no")).encode())
                    
                    f.write(("images-table = %s\n" % tbl_file_rel).encode())
                    f.write(("nvcounter-id = %d\n" % (__req.nv_counter_id)).encode())
                    f.write(("nvcounter-val = %s\n" % (__req.nv_counter_val)).encode())
                    f.write(("%s = %s\n" % (key_cert_tool.PARAM_HASH_OUT, has_out_file_rel)).encode())
                    f.write(("cert-pkg = %s\n" % (out_cert_file_rel)).encode())
                if (DEBUG): logD("Write done")
            except:
                traceback.print_exc()
                if (DEBUG): logD("Write failed")
                return SignResp(__req, -1, "write cfg failed")
            
            command = "%s %s --type=content --cfg=%s" % (
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
            if res == 0 :
                # convert cert bin to srec
                srecfile = os.path.join(signed_image_folder, "%s.srec" % out_cert_fname)
                command = "%s %s --input=%s --output=%s --target=srec --vma=%s" % (
                    bin_connvert_script, # sign script
                    "-v" if DEBUG else "",
                    out_cert_file,
                    srecfile,
                    __req.adjust_vma
                )
                log("Convert %s to srec" % out_cert_fname, TAG)
                if (DEBUG): logD("command %s" % command, TAG)
                ret = common.runCommand(command)
                if (ret != common.ERR_NONE):
                    msg = "Convert %s to srec failed" % out_cert_file
                    logE(msg, TAG)
                    return SignResp(__req, common.ERR_FAILED, msg)
            else :
                logE("Signed failed with command %s, res %s" % (command, str(res)), TAG, True)
                return SignResp(__req, -1, "Signed failed %s" % str(res))

            found += 1

        if (ret != common.ERR_NONE):
            return SignResp(__req, ret, msg)
        else:
            if found > 0:
                # copy public key info
                from server.key.renesas.key_cert_tool import SB_CERT_FNAME
                from server.key.renesas.key_cert_tool import SB_CERT_FNAME2
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
                
                # copy uploaded binaries to output
                if __req.include_in_bin:
                    log("Copy uploaded files to outdir", TAG)
                    org_bin_dir = os.path.join(signed_image_folder, UPLOAD_BINARIES)
                    common.mkdir(org_bin_dir)
                    for _fname in os.listdir(uploaded_bin_dir):
                        bin_file = os.path.join(uploaded_bin_dir, _fname)
                        shutil.copy(bin_file, org_bin_dir)
                
                # search and copy encrypted file to output
                log("Copy binary files to outdir", TAG)
                out_bin_dir = os.path.join(signed_image_folder, IN_BINARY_NAME)
                common.mkdir(out_bin_dir)
                if (DEBUG): logD("memory_map_dict %s" % str(memory_map_dict), TAG)
                for _fname in os.listdir(input_bin_dir):
                    bin_file = os.path.join(input_bin_dir, _fname)
                    shutil.copy(bin_file, out_bin_dir)
                    log("convert bin to srec", TAG)
                    [_memaddr, _] = memory_map_dict[_fname] if _fname in memory_map_dict else [None, None]
                    if _memaddr is not None:
                        __name, _ = os.path.splitext(_fname)
                        srecfile = os.path.join(out_bin_dir, "%s.srec" % __name)
                        command = "%s %s --input=%s --output=%s --target=srec --vma=%s" % (
                            bin_connvert_script, # sign script
                            "-v" if DEBUG else "",
                            bin_file,
                            srecfile,
                            _memaddr
                        )
                        log("Convert %s to srec" % file, TAG)
                        if (DEBUG): logD("command %s" % command, TAG)
                        ret = common.runCommand(command)
                        if (ret != common.ERR_NONE):
                            msg = "Convert %s to srec failed" % bin_file
                            logE(msg, TAG)
                            return SignResp(__req, common.ERR_FAILED, msg)
                    else:
                        logE(msg, "Not found memory map to convert srec %s" % bin_file)
                        return SignResp(__req, common.ERR_FAILED, "Not found memory map to conver srec %s" % _fname)

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
        
        if (__code == common.ERR_NONE and __req.root_key_info != None):
            [__code, __msg] = self.prepareKey(__req, __req.root_key_info, __req.key_dir, fnames=[ROOT_AES_KEY_FNAME])
        # else:
        #     log("do_sign, use default key", TAG)

        if (__code != common.ERR_NONE):
            applog.logE("Prepare key failed %d" % __code)
            return SignResp(__req, __code, __msg)
       
        return self.sign_target(__req)


    # Get template render for webpage used to manual sign
    def get_html_render_for_manual_sign(self, request):
        from server.key.key_mng import keyMgr
        from server.sign import signfactory as signfactory
        key_list = keyMgr().get_all_keys(tool=RENESAS_TOOL_NAME, keytool=RENESAS_KEY_CERT_TOOL_NAME)
        root_key_list = keyMgr().get_all_keys(tool=RENESAS_TOOL_NAME, keytool=RENESAS_ROOT_KEY_TOOL_NAME)
        
        return render_template(
            "sign/sign_renesas.html"
            # common for headers
            , login=is_login(request)
            , username=current_username()
            # common for sign
            , module="Renesas: Generate Content Certificate"
            , project_list=getProjectList()
            , model_list=getModelList()
            , key_list=key_list
            , default_key_id=common.DEFAULT_KEY_ID
            , root_key_list=root_key_list
            , default_root_key_id=common.DEFAULT_KEY_ID
            , none_root_key_id=common.NONE_KEY_ID
            , toolname=RENESAS_TOOL_NAME
            , rootkeytoolname=RENESAS_ROOT_KEY_TOOL_NAME
            , keytoolname=RENESAS_KEY_CERT_TOOL_NAME
            , default_adjust_vma=DEFAULT_ADJUST_VMA
            )


    def getKeyToolList(self):
        return [RENESAS_KEY_CERT_TOOL_NAME, RENESAS_ROOT_KEY_TOOL_NAME, RENESAS_SB_KEY_TOOL_NAME]