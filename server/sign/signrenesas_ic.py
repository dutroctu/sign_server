#!/usr/bin/env python
#
#  SIGN FOT TBOX
#
from socket import CMSG_LEN
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
from server.common import DEFAULT as DEFAULT, ERR_NONE
from server import hash as hash
from server.app import getProjectList
from server.app import getModelList
from server.sign.signresp import SignResp
import server.sign.signfactory
import server.login.session

import zipfile
import shutil
from server.login.login import is_login, current_username
import traceback


from server.sign import signfactory as signfactory

from server.app import getRootToolDir
from server.storage import storageMgr
from server.key.renesas import key_cert_tool
from server.key.renesas.key_cert_tool import RENESAS_KEY_CERT_TOOL_NAME
from server.key.renesas.key_cert_tool import RENESAS_SIGN_TOOL_ZIP_PATH
from server.key.renesas.key_cert_tool import SIGNING_TOOL_SCRIPT
from server.key.renesas.key_cert_tool import RENESAS_TOOL_DIR_NAME

from server.key.renesas.sb_key_tool import RENESAS_SB_KEY_TOOL_NAME

from server.key.renesas.root_key_tool import RENESAS_ROOT_KEY_TOOL_NAME
from server.key.renesas.root_key_tool import ROOT_AES_KEY_FNAME


from server.common import INVALID_KEY_ID
from server.sign.signrenesas import RENESAS_TOOL_NAME
from server.sign import renesas_ic_param
from server.sign.renesas_ic_param import Param
from server.sign.renesas_ic_param import MemoryMap
from server.sign.renesas_ic_param import ParamList
from server.sign.renesas_ic_param import PARAM_CUSTOM_BOOT_FILE
from server.sign.renesas_ic_param import getListParam
from server.sign.renesas_ic_param import getParam
from server.sign.renesas_ic_param import addNewParam

from server.sign.renesas_ic_param import ENCRYPTION_MODE_DISABLE
from server.sign.renesas_ic_param import ENCRYPTION_MODE_ENABLE_NO_IV
from server.sign.renesas_ic_param import ENCRYPTION_MODE_ENABLE_WITH_IV


TAG = "signrenesas_ic"
RENESAS_IC_TOOL_NAME = "renesas_image_create"
RENESAS_IC_TOOL_DESC = "Renesas - Image Creation"

# command timeout, to avoid locking server (i.e. key need password, but no password is set)
# COMMAND_TIMEOUT_SECOND=300
COMMAND_TIMEOUT_MIN=30
COMMAND_TIMEOUT_SECOND=(COMMAND_TIMEOUT_MIN*60)

INPUT_IMAGE_IND_TAG = "image"
INPUT_IMAGE_IND_TBL_TAG = "image_tbl"
INPUT_IMAGE_IND_MEM_TAG = "image_mem"
INPUT_IMAGE_IND_FLASH_TAG = "image_flash"

CONVERT_SCRIPT="srec2bin.sh"

PARAM_DIR_NAME = "param"
PARAM_DIR_PATH = os.path.join(getRootToolDir(), RENESAS_TOOL_DIR_NAME, PARAM_DIR_NAME)

IC_DIR_NAME = "ImageCreate"

IC_SCRIPT_NAME = "sign.sh"
IC_SCRIPT_REL_PATH = os.path.join(IC_DIR_NAME, IC_SCRIPT_NAME)

IC_SETTING_DIR_NAME = "setting"
IC_SETTING_DIR_REL_PATH = os.path.join(IC_DIR_NAME, IC_SETTING_DIR_NAME)

IC_INPUT_DIR_NAME = "input"
IC_INPUT_DIR_REL_PATH = os.path.join(IC_DIR_NAME, IC_INPUT_DIR_NAME)

IC_INPUT_BIN_DIR_NAME = "binary"
IC_INPUT_BIN_DIR_REL_PATH = os.path.join(IC_INPUT_DIR_REL_PATH, IC_INPUT_BIN_DIR_NAME)

IC_INPUT_BIN_PARAM_DIR_NAME = "param"

IC_OUTPUT_DIR_NAME = "output"
IC_OUTPUT_DIR_REL_PATH = os.path.join(IC_DIR_NAME, IC_OUTPUT_DIR_NAME)

IC_SETTING_BOOT_DIR_NAME = "bootparam"
IC_SETTING_BOOT_DIR_REL_PATH = os.path.join(IC_SETTING_DIR_REL_PATH, IC_SETTING_BOOT_DIR_NAME)

IC_SETTING_CERT_DIR_NAME = "cert_header"
IC_SETTING_CERT_DIR_REL_PATH = os.path.join(IC_SETTING_DIR_REL_PATH, IC_SETTING_CERT_DIR_NAME)



CONTENT_CERT_CFG_FNAME = "sb_cnt_cert.cfg"
CONTENT_CERT_BIN_FNAME = "sb_cnt_cert.bin"
CONTENT_HAST_OUT_FNAME = "hashout.bin"

ENC_FILE_SUFFIX = "_enc"
CERT_FILE_SUFFIX = "_cert"

###################################################################
# Signing request
###################################################################
class SignRequestRenesasIC(SignRequest):

    # for content certification
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
    encryption_mode = 1 # 1: disable, 2: enable but not output iv, 3: enable and output iv

    # id of param to be used
    boot_param = None

    # custom information for param
    custom_map = None
    custom_param = None
    custom_cert_param = None
    custom_name = None
    custom_platform = None
    file_mapping = None
    adjust_vma = None
    saveParam = False  # save param or not
    name = None  # name of param (for custom param)
    desc = None # description/help
    is_enc = False

    def __init__(self, request):
        if (DEBUG): logD("SignRequestRenesasIC init", TAG)
        super(SignRequestRenesasIC, self).__init__(request, RENESAS_IC_TOOL_NAME)
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


        self.boot_param = None
        self.custom_map = None
        self.custom_param = None
        self.custom_cert_param = None
        self.custom_name = None
        self.custom_platform = None
        self.file_mapping = None
        self.adjust_vma = None
        self.saveParam = False
        self.name = None
        self.desc = None
        self.is_enc = False

        self.nv_counter_id = common.extract_form_request(request, key_cert_tool.PARAM_NV_COUNTER_ID, is_int=True, default_data=0)
        self.nv_counter_val = common.extract_form_request(request, key_cert_tool.PARAM_NV_COUNTER_VAL, is_int=True, default_data=0)
        self.encryption_mode = common.extract_form_request(request, "encryption_mode", is_int=True, default_data=1)

        if self.encryption_mode == ENCRYPTION_MODE_ENABLE_NO_IV or self.encryption_mode == ENCRYPTION_MODE_ENABLE_WITH_IV:
            self.is_enc = True
        
        log("encryption_mode %d" % self.encryption_mode, TAG)

        self.boot_param = common.extract_form_request(request, "boot_param", is_int=False, default_data=None)

        # custom info
        self.custom_map = common.extract_form_request(request, "custom_map", is_int=False, default_data=None)
        self.custom_boot_param = common.extract_form_request(request, "custom_boot_param", is_int=False, default_data=None)
        self.custom_cert_param = common.extract_form_request(request, "custom_cert_param", is_int=False, default_data=None)
        self.custom_name = common.extract_form_request(request, "custom_name", is_int=False, default_data=None)
        self.custom_platform = common.extract_form_request(request, "custom_platform", is_int=False, default_data=renesas_ic_param.PLATFORM_DEFAULT)
        self.adjust_vma = common.extract_form_request(request, "adjust_vma", is_int=False, default_data=None)
        self.file_mapping = common.extract_form_request(request, "file_mapping", is_int=False, default_data=None)
        self.name = common.extract_form_request(request, "custom_name", is_int=False, default_data=None)
        self.desc = common.extract_form_request(request, "custom_desc", is_int=False, default_data=None)
        saveParam = common.extract_form_request(request, "save_new_param", is_int=False, default_data=False)

        self.saveParam = common.isRequestSelected(saveParam)
        if (DEBUG): logD("saveParam %s" %(self.saveParam), TAG)

        if (DEBUG): logD("get key info", TAG)
        [self.key_id, self.key_info] = self.getKeyInfo(request, "key_id", "key_name", RENESAS_KEY_CERT_TOOL_NAME, RENESAS_TOOL_NAME)
        [self.root_key_id, self.root_key_info] = self.getKeyInfo(request, "root_key_id", "root_key_name", RENESAS_ROOT_KEY_TOOL_NAME, RENESAS_TOOL_NAME)
        if (DEBUG): logD("key id '%s'" % self.key_id, TAG)
        
    
    def toString(self, isFull=False):
        ret_str = ""
        ret_str += "boot_param: %s;\n" % self.boot_param
        ret_str += "custom_platform: %s;\n" % self.custom_platform
        ret_str += "\n"
        return ret_str

    # return dic of keyinfo, with key is keytype, value is key_info
    def getListKeyInfo(self):
        return {
            "key_info":self.key_info,
            "root_key_info":self.root_key_info
            }
    def getSignInfo(self):
        return {
            "boot_param":self.boot_param,
            "custom_platform":self.custom_platform
            }

###################################################################
# 
###################################################################
class SignRenesasIC(SignTool):

    def getName(self, desc=False):
        return RENESAS_IC_TOOL_NAME if not desc else RENESAS_IC_TOOL_DESC

    def parse_request(self, request):
        if (DEBUG): logD("SignRenesasIC parse_request")
        return SignRequestRenesasIC(request)

    def check(self, __req):
        [__code, __msg] = super(SignRenesasIC, self).check(__req)

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

        if __req.encryption_mode < 1 or __req.encryption_mode > 3:
            __result_code = -1
            __result_str += "invalid encryption_mode %d" % __req.encryption_mode


        if common.isValidString(__req.boot_param) is None:
            __result_code = -1
            __result_str += "No valid param info"

        if __result_code == 0 and __req.saveParam and not common.isValidString(__req.name) is not None :
            __result_code = -1
            __result_str += "invalid/not param name"

        if (__result_code == 0):
            __result_str = "OK"

        return [__result_code, __result_str]

    # prepare param, return [code, msg]
    def prepareParam(self, __req, target_dir):
        if (DEBUG): logD("prepareParam", TAG)
        if (DEBUG): logD("target_dir %s" % target_dir, TAG)

        if __req is not None and __req.boot_param is not None and len(__req.boot_param) > 0:
            
            if not os.path.exists(PARAM_DIR_PATH):
                logE("not found param dir %s" % PARAM_DIR_PATH, TAG, True)
                return [common.ERR_NOT_FOUND, "Not found param dir"]

            param = None

            log("Prepare existinng param %s" % __req.boot_param, TAG)
            param = getParam(__req.boot_param)
            if param is None:
                logE("Not found param %s " % __req.boot_param, TAG)
                return [common.ERR_NOT_FOUND, "Not found boot param"]
                
            log("Prepare custom param", TAG)
            if PARAM_CUSTOM_BOOT_FILE in __req.file_dir_list:
                param.boot_bin = __req.file_dir_list[PARAM_CUSTOM_BOOT_FILE]
            log("boot_bin to use %s" % param.boot_bin)
            if renesas_ic_param.PARAM_CUSTOM_CERT_FILE in __req.file_dir_list:
                cert_bin = __req.file_dir_list[renesas_ic_param.PARAM_CUSTOM_CERT_FILE]
                if os.path.exists(cert_bin):
                    param.cert_bin = cert_bin
            log("cert_bin to use %s" % param.cert_bin)
            if __req.custom_map is not None and len(__req.custom_map) > 0:
                val = os.path.join(__req.in_working_folder, "memory_map")
                if common.write_string_to_file(val, __req.custom_map):
                    param.memory_map = val
                else:
                    logE("write custom_map to file failed %s " % val, TAG)
                    return [common.ERR_FAILED, "prepare custom_map failed"]

            if __req.custom_boot_param is not None and len(__req.custom_boot_param) > 0:
                val = os.path.join(__req.in_working_folder, "boot_param")
                if common.write_string_to_file(val, __req.custom_boot_param):
                    param.boot_param = val
                else:
                    logE("write boot_param to file failed %s " % val, TAG)
                    return [common.ERR_FAILED, "prepare custom_boot_param failed"]

            if __req.custom_cert_param is not None and len(__req.custom_cert_param) > 0:
                val = os.path.join(__req.in_working_folder, "cert_param")
                if common.write_string_to_file(val, __req.custom_cert_param):
                    param.cert_param = val
                else:
                    logE("write cert_param to file failed %s " % val, TAG)
                    return [common.ERR_FAILED, "prepare custom_cert_param failed"]

            if __req.desc is not None and len(__req.desc) > 0:
                val = os.path.join(__req.in_working_folder, "help")
                if common.write_string_to_file(val, __req.desc):
                    param.help = val
                else:
                    logE("write help to file failed %s " % val, TAG)
                    return [common.ERR_FAILED, "prepare help failed"]

            if __req.custom_name is not None and len(__req.custom_name) > 0:
                param.name = __req.custom_name

            if __req.adjust_vma is not None and len(__req.adjust_vma) > 0:
                param.adjust_vma = __req.adjust_vma
                # TODO: validate vma value
            
            if __req.custom_platform is not None and len(__req.custom_platform) > 0:
                param.custom_platform = __req.custom_platform
                # TODO: validate custom_platform value
                
            # parse file mapping
            filemapping = common.isValidString(__req.file_mapping)
            filemap = {}
            ret = common.ERR_NONE
            msg = ""
            # file mapping format: <file name no ext> <target>
            if filemapping is not None:
                if (DEBUG): logD("Parse file mapping", TAG)
                if (DEBUG): logD(filemapping, TAG)
                lines = filemapping.splitlines()
                for line in lines:
                    if (DEBUG): logD("line %s" % line, TAG)
                    line = common.isValidString(line)
                    if line is not None:
                        items = line.split()
                        if items is not None and len(items) > 1:
                            fname = common.isValidString(items[0])
                            target = common.isValidString(items[1])
                            if fname is not None and target is not None:
                                name, _ = os.path.splitext(fname)
                                if target not in filemap.keys() and name not in filemap.values():
                                    filemap[target] = name
                                else:
                                    ret = common.ERR_INVALID_ARGS
                                    msg = "target or name existed %s/%s" % (target, name)
                                    break
                        else:
                            ret = common.ERR_INVALID_ARGS
                            msg = "Invalid mapping param %s" % line
                            break
            
            if ret == common.ERR_NONE: 
                [ret, msg] = param.prepareParam(target_dir, filemap)

            if ret == common.ERR_NONE:
                return [ret, param]
            else:
                return [ret, msg]
        else:
            logE("invalid param", TAG)
            return [common.ERR_NOT_FOUND, "invalid param"]

    # Sign target file
    def sign_firmware(self, __req):

        ret = common.ERR_NONE
        msg = None
        log_srec_convert = ""
        log("sign_target, uuid %s" % str(__req.session.uuid), TAG)
        # get script to sign
        if not os.path.exists(__req.tool_working_folder):
            logE("%s not found" % __req.tool_working_folder, TAG, True)
            return SignResp(__req, -1, "Not found tool to sign")

        if __req.key_dir is None or not os.path.exists(__req.key_dir):
            logE("not found keydir", TAG, True)
            return SignResp(__req, -1, "not found keydir")
        
        # content certification script
        sign_script = os.path.join(__req.tool_working_folder, SIGNING_TOOL_SCRIPT)
        if (DEBUG): logD("sign_script %s" % sign_script)
        if not os.path.exists(sign_script):
            msg = "sign_script not found %s" % SIGNING_TOOL_SCRIPT
            logE(msg, TAG, True)
            return SignResp(__req, common.ERR_NOT_FOUND, msg)

        # image create script
        ic_script = os.path.join(__req.tool_working_folder, IC_SCRIPT_REL_PATH)
        if (DEBUG): logD("ic_script %s" % ic_script)
        if not os.path.exists(ic_script):
            msg = "ic_script not found %s" % IC_SCRIPT_REL_PATH
            logE(msg, TAG, True)
            return SignResp(__req, common.ERR_NOT_FOUND, msg)
        
        # bin vs srec convert script
        bin_connvert_script = os.path.join(__req.tool_working_folder, CONVERT_SCRIPT)
        if (DEBUG): logD("bin_connvert_script %s" % bin_connvert_script)
        if not os.path.exists(bin_connvert_script):
            msg = "bin_connvert_script not found %s" % CONVERT_SCRIPT
            logE(msg, TAG, True)
            return SignResp(__req, common.ERR_NOT_FOUND, msg)
        
        # folder to contain certification
        signed_image_folder = os.path.join(__req.tool_working_folder, "signed")
        common.mkdir(signed_image_folder)

        # input folder of image create
        ic_input_dir = os.path.join(__req.tool_working_folder, IC_INPUT_DIR_REL_PATH)
        common.mkdir(ic_input_dir)

        # output folder of image create
        ic_out_dir = os.path.join(__req.tool_working_folder, IC_OUTPUT_DIR_REL_PATH)
        common.mkdir(ic_out_dir)

        # input binary folder of image create
        ic_bin_dir = os.path.join(ic_input_dir, IC_INPUT_BIN_DIR_NAME)
        common.mkdir(ic_bin_dir)

        # input param folder of image create
        ic_bin_param_dir = os.path.join(ic_input_dir, IC_INPUT_BIN_DIR_NAME, IC_INPUT_BIN_PARAM_DIR_NAME)
        common.mkdir(ic_bin_param_dir)

        # prepare key
        log("Prepare sign keys", TAG)
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
        
        
        log("Prepare encrypt keys", TAG)
        aesKey = None
        aesKeyRel = None
        if __req.root_key_info is not None and __req.encryption_mode > 1:
            aesKey = os.path.join(__req.key_dir, ROOT_AES_KEY_FNAME)
            if not os.path.exists(aesKey):
                logE("prepare encryption key failed", TAG)
                return SignResp(__req, -1, "prepare encryption key failed")
            aesKeyRel = os.path.relpath(aesKey, __req.tool_working_folder)

        if (DEBUG): logD("file_path_list %s" % str(__req.file_path_list), TAG)

        IN_BINARY_NAME="in_bin"
        IN_TBL_NAME="in_tbl"

        # Prepare files
        input_bin_dir = os.path.join(__req.tool_working_folder, IN_BINARY_NAME)
        common.mkdir(input_bin_dir)
        if (DEBUG): logD("input_bin_dir %s" % input_bin_dir, TAG)

        input_tbl_dir = os.path.join(__req.tool_working_folder, IN_TBL_NAME)
        common.mkdir(input_tbl_dir)
        if (DEBUG): logD("input_tbl_dir %s" % input_tbl_dir, TAG)

        # binaries
        log("Prepare binaries, convert srec to bin if need", TAG)
        if INPUT_IMAGE_IND_TAG in __req.file_dir_list:
            try:
                img_dir = __req.file_dir_list[INPUT_IMAGE_IND_TAG]
                if (DEBUG): logD("img_dir %s" % img_dir, TAG)
                if common.isValidString(img_dir) is None or not os.path.exists(img_dir):
                    logE("No image is uploaded", TAG)
                    return SignResp(__req, -1, "No image is uploaded")

                for fname in os.listdir(img_dir): 
                    name, ext = os.path.splitext(fname)
                    file = os.path.join(img_dir, fname)
                    # conver srec to bin
                    if ext in common.SREC_EXT:
                        binfname = "%s.bin" % name
                        binfile = os.path.join(input_bin_dir, binfname)
                        command = "%s %s --input=%s --output=%s --target=bin" % (
                            bin_connvert_script, # sign script
                            "-v" if DEBUG else "",
                            file,
                            binfile
                        )
                        log("Convert %s to bin" % fname, TAG)
                        if (DEBUG): logD("command %s" % command, TAG)
                        ret = common.runCommand(command)
                        if (ret == common.ERR_NONE):
                            log_srec_convert += "Convert SREC %s to BIN %s: OK \n" % (fname, binfname)
                        else:
                            msg = "Convert %s to bin failed" % fname
                            logE(msg, TAG)
                            return SignResp(__req, ret, msg)
                    # extract zip file
                    elif common.isZipFile(file):
                        log("Extract zip file %s" % fname, TAG)
                        unzipdir = os.path.join(img_dir, name)
                        common.mkdir(unzipdir)
                        if (DEBUG): logD("extract zip from %s to %s" %(file, unzipdir), TAG)
                        with zipfile.ZipFile(file, 'r') as zip_ref:
                            zip_ref.extractall(unzipdir)
                        for zfname in os.listdir(unzipdir): 
                            zname, zext = os.path.splitext(zfname)
                            zfile = os.path.join(unzipdir, fname)
                            if zext in common.SREC_EXT:
                                zbinfname = "%s.bin" % zname
                                zbinfile = os.path.join(input_bin_dir, zbinfname)
                                zcommand = "%s %s --input=%s --output=%s --target=bin" % (
                                    bin_connvert_script, # sign script
                                    "-v" if DEBUG else "",
                                    zfile,
                                    zbinfile
                                )
                                log("Convert %s to bin" % zfname, TAG)
                                if (DEBUG): logD("command %s" % zcommand, TAG)
                                ret = common.runCommand(zcommand)
                                if (ret == common.ERR_NONE):
                                    log_srec_convert += "Convert SREC %s to BIN %s: OK \n" % (zfname, zbinfname)
                                else:
                                    msg = "Convert %s to bin failed" % zfname
                                    logE(msg, TAG)
                                    return SignResp(__req, ret, msg)
                            else:
                                shutil.copy(zfile, input_bin_dir)
                    else:
                        shutil.copy(file, input_bin_dir)

                if (DEBUG): logD("Add padding for file in %s" % input_bin_dir, TAG)
                for fname in os.listdir(input_bin_dir): 
                    file = os.path.join(input_bin_dir, fname)
                    sz = os.path.getsize(file)
                    mod = sz % 16
                    if (DEBUG): logD("padding file %s, sz %d" % (file, sz), TAG)
                    if mod != 0:
                        log("Add PADDING for %s, mod %d" % (fname, mod), TAG)
                        padded = [0] * (16 - mod)
                        log_srec_convert += "Add PADDING for %s padded %d bytes\n" % (fname, len(padded))
                        with open(file, "ab") as f:
                            f.write(bytearray(padded))
            except:
                traceback.print_exc()
                return SignResp(__req, common.ERR_EXCEPTION, "Exception when prepare binary file")

        else:
            logE("not found any binaries", TAG)
            return SignResp(__req, common.ERR_NOT_FOUND, "Not bin file to sign")

        # prepare parameter for image create
        log("Prepare parameter", TAG)
        [ret, msg] = self.prepareParam(__req, ic_bin_param_dir)
        if (ret != common.ERR_NONE) or msg is None or not isinstance(msg, Param):
            return SignResp(__req, ret, msg)
        param = msg

        # program address files (tbl)
        log("Prepare program address files (tbl)", TAG)
        log("input_bin_dir %s" % input_bin_dir, TAG)
        for fname in os.listdir(input_bin_dir):
            log("fname %s" % fname, TAG)
            tbl_file = None
            name, _ = os.path.splitext(fname)
            # make tbl file for each binary, basing on memory map
            if name in param.memory_map_dict:
                map = param.memory_map_dict[name]
                tbl_file = os.path.join(input_tbl_dir, "%s.tbl" % name)
                try:
                    with open(tbl_file, "w") as f:
                        # In R-Car Series 3rd Generation, the 64-bits flash store address needs to specify the same address as the 64-bits
                        # memory load address
                        if param.platform == renesas_ic_param.PLATFORM_RCARH3:
                            f.write("%s %s %s\n" % (fname, map.mem_addr, map.mem_addr))
                        else:
                            f.write("%s %s %s\n" % (fname, map.mem_addr, map.flash_addr))
                except:
                    traceback.print_exc()
                    return SignResp(__req, common.ERR_EXCEPTION, "Exception when prepare tbl file for %s" % name)
            else:
                ret = common.ERR_FAILED
                msg = "%s not found on memory map" % fname
                logE(msg, TAG)
                break

        # check for each program address file
        log("Scan for each table files to make content cert", TAG)
        found = 0
        if (DEBUG): logD("input_tbl_dir %s" % input_tbl_dir, TAG)
        
        outcertlist = []
        for fname in os.listdir(input_tbl_dir):
            if (DEBUG): logD("fname %s" % fname, TAG)

            name_no_ext, _ = os.path.splitext(fname)
            # FIXME: uhm, call twice with above, should optimize it....
            if name in param.memory_map_dict:
                map = param.memory_map_dict[name_no_ext]
            else:
                ret = common.ERR_FAILED
                msg = "file %s not found in memory map" % fname
                logE(msg)
                break

            tbl_file = os.path.join(input_tbl_dir, fname)
            tbl_file_to_signed = os.path.join(signed_image_folder, fname)
            if (DEBUG): logD("tbl_file %s" % tbl_file, TAG)

            if not os.path.isfile(tbl_file):
                continue

            # read tble file
            try:
                with open(tbl_file) as f:
                    content = f.readlines()

                content = [x.strip() for x in content] 

                # rewrite for new path
                with open(tbl_file_to_signed, "w") as f:
                    for line in content:
                        f.write("%s/%s\n" % (IN_BINARY_NAME, line))
            except:
                traceback.print_exc()
                logE("parse program table file failed", TAG)
                return SignResp(__req, common.ERR_FAILED, "parse program table file failed")

            cfg_file = os.path.join(signed_image_folder, CONTENT_CERT_CFG_FNAME)

            tbl_file_rel = os.path.relpath(tbl_file_to_signed, __req.tool_working_folder)
            tblfname = os.path.basename(tbl_file_to_signed)
            tblname, _ = os.path.splitext(tblfname)


            has_out_file = os.path.join(signed_image_folder, "%s.hash" % tblname)
            has_out_file_rel = os.path.relpath(has_out_file, __req.tool_working_folder)

            
            out_cert_file = os.path.join(signed_image_folder, "%s.cert" % tblname)
            out_cert_file_rel = os.path.relpath(out_cert_file, __req.tool_working_folder)

            # build config file
            try:
                with open(cfg_file, 'wb+') as f:
                    f.write(b"[CNT-CFG]\n")

                    f.write(("%s = %s\n" % (key_cert_tool.PARAM_ROOT_KEY_FILE, privKeyRel)).encode())
                    f.write(("%s = %s\n" % (key_cert_tool.PARAM_ROOT_KEY_PASS, privKeypwdRel)).encode())
                    if aesKeyRel is not None:
                        f.write(("%s = %s\n" % (key_cert_tool.PARAM_AES_ENC_KEY, aesKeyRel)).encode())
                    
                    f.write(("%s = %s\n" % (key_cert_tool.PARAM_AES_IV_GET, "yes" if __req.encryption_mode == 3 else "no")).encode())
                    
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
            
            # run command to generate content certification
            command = "%s %s --type=content --cfg=%s" % (
                sign_script, # sign script
                "-v" if DEBUG else "",
                cfg_file
                )
            
            log("Signing script: %s" % sign_script, TAG)
            if (DEBUG): logD ("command: " + str(command), TAG)

            res = 0

            # run signing script
            log(">> Start generate content certification for %s" % fname, TAG)
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
                logE("Signed failed with command %s, res %s" % (command, str(res)), TAG, True)
                return SignResp(__req, -1, "Signed failed %s" % str(res))


            # copy cert file to image create input, rename to target file
            ic_cert_in = os.path.join(ic_bin_dir, "%s_cert.bin" % map.target)
            if (DEBUG): logD("out_cert_file %s --> ic_cert_in %s" % (out_cert_file, ic_cert_in), TAG)
            shutil.copy(out_cert_file, ic_cert_in)
            outcertlist.append(ic_cert_in)
            found += 1

        if (ret != common.ERR_NONE):
            return SignResp(__req, ret, msg)
        else:
            if found > 0: #

                #
                # Start to generate boot param and cert header using IMAGE CREATE
                #

                ret = common.ERR_NONE
                
                log(">> Copy firmware file to image creator dir", TAG)
                if (DEBUG): logD("%s --> %s" % (input_bin_dir,ic_bin_dir), TAG)

                for fname in os.listdir(input_bin_dir):
                    shutil.copy(os.path.join(input_bin_dir, fname), ic_bin_dir)


                log(">> Copy content cert to ic dir", TAG)
                # copy public key info (sb_cert)
                from server.key.renesas.key_cert_tool import SB_CERT_FNAME
                from server.key.renesas.key_cert_tool import SB_CERT_FNAME2
                key = os.path.join(__req.key_dir, SB_CERT_FNAME)
                if os.path.exists(key):
                    if (DEBUG): logD("copy %s to %s" % (key, signed_image_folder), TAG)
                    shutil.copy(key, ic_bin_dir)
                else:
                    key = os.path.join(__req.key_dir, SB_CERT_FNAME2)
                    if os.path.exists(key):
                        pubkey = os.path.join(ic_bin_dir, SB_CERT_FNAME)
                        if (DEBUG): logD("copy %s to %s" % (key, pubkey), TAG)
                        shutil.copy(key, pubkey)
                    else:
                        msg = "No %s key" % SB_CERT_FNAME
                        ret = common.ERR_NOT_FOUND
                        logE(msg, TAG)
                
                ifiles = []
                for fname in os.listdir(ic_bin_dir):
                    fpath = os.path.join(ic_bin_dir, fname)
                    if os.path.isfile(fpath):
                        if (DEBUG): logD("add fname %s to ifiles"  % fname, TAG)
                        ifiles.append(fname)
                    else:
                        if (DEBUG): logD("fname %s is not file, skip adding to ifiles"  % fname, TAG)

                # build param
                paramfiles = []
                ic_out_param_dir =  os.path.join(ic_out_dir, "param")
                common.mkdir(ic_out_param_dir)
                for fname in os.listdir(ic_bin_param_dir):
                    paramfiles.append(fname)
                    shutil.copy(os.path.join(ic_bin_param_dir, fname), ic_out_param_dir)

                # TODO: flash param?
                if (DEBUG): logD("ifiles %s"  % str(ifiles), TAG)
                if (DEBUG): logD("paramfiles %s"  % str(paramfiles), TAG)
                
                bootfile = os.path.join(ic_input_dir, "bootparam.txt")
                ic_bin_rel = os.path.join(IC_INPUT_DIR_NAME, IC_INPUT_BIN_DIR_NAME)
                ic_bin_param_rel = os.path.join(ic_bin_rel, IC_INPUT_BIN_PARAM_DIR_NAME)

                if ret == common.ERR_NONE and param.boot_param_dict is not None and len(param.boot_param_dict) > 0:
                    log(">> Prepare boot param", TAG)
                    if (DEBUG): logD("boot_param_dict %s" % str(param.boot_param_dict), TAG)
                    with open(bootfile, "w") as f:
                        for file,offset in param.boot_param_dict.items():
                            if (DEBUG): logD("file %s" % file, TAG)
                            name, ext = os.path.splitext(file)
                            file_enc = None
                            if __req.is_enc and not name.endswith(ENC_FILE_SUFFIX):
                                file_enc = name + ENC_FILE_SUFFIX + ext
                                if (DEBUG): logD("file_enc %s" % file_enc, TAG)
                            
                            if file_enc is not None and file_enc in ifiles:
                                bootitem = "../%s/%s %s\n" % (ic_bin_rel, file_enc, offset)
                                if (DEBUG): logD("file_enc in ifiles bootitem %s" % bootitem, TAG)
                                f.write(bootitem)
                            elif file in ifiles:
                                bootitem = "../%s/%s %s\n" % (ic_bin_rel, file, offset)
                                if (DEBUG): logD("file in ifiles bootitem %s" % bootitem, TAG)
                                f.write(bootitem)
                            elif file in paramfiles:
                                bootitem = "../%s/%s %s\n" % (ic_bin_param_rel, file, offset)
                                if (DEBUG): logD("file in paramfiles bootitem %s" % bootitem, TAG)
                                f.write(bootitem)
                            else:
                                log("boot file %s not found in boot bin/ic/param dirs" % file, TAG)
                                # not found file with file name in boot param
                                # try to replace it with real file name and search again
                                fname = None
                                for map in param.memory_map_dict.values():
                                    if name == map.target:
                                        fname = common.isValidString(map.fname)
                                        if fname is not None:
                                            # For flash writer, currently, it's quite special that boot parram will include flashwriter bintary
                                            # for normal binaries, boot param only include boot pararm bin and cert file
                                            # in case of encryption, binaries will include "_enc" in end of file name
                                            # FIXME: make it more dynamically???
                                            if param.binary_type == common.FLASHWRITER and __req.is_enc:
                                                fname = fname + ENC_FILE_SUFFIX
                                            fname = fname + ext
                                        break
                                if fname is not None:
                                    if fname in ifiles:
                                        log("replace default one with file name in memory map %s" % fname, TAG)
                                        f.write("../%s/%s %s\n" % (ic_bin_rel, fname, offset))
                                    else:
                                        logE("Not found %s in %s" % (fname, ic_bin_rel), TAG)
                                else:
                                    logE("Not found any thing, stupid, out", TAG)
                
                certfile = os.path.join(ic_input_dir, "cert_header.txt")
                if ret == common.ERR_NONE and param.cert_param_dict is not None and len(param.cert_param_dict) > 0:
                    log(">> Prepare cert header param", TAG)
                    with open(certfile, "w") as f:
                        for file,offset in param.cert_param_dict.items():
                            if (DEBUG): logD("file %s" % file, TAG)
                            if file in ifiles:
                                f.write("../%s/%s %s\n" % (ic_bin_rel, file, offset))
                            elif file in paramfiles:
                                f.write("../%s/%s %s\n" % (ic_bin_param_rel, file, offset))
                            else:
                                log("cert header file %s not found in cert bin dirs" % file, TAG)
                else:
                    certfile = None
                
                # call script to generate images
                if ret == common.ERR_NONE:
                    log(">> Execute image create", TAG)
                    command = "%s %s --boot=\"%s\" --cert=\"%s\" --output=\"%s\" --vma=%s" % (
                        ic_script, # sign script
                        "-v" if DEBUG else "",
                        bootfile,
                        certfile if certfile is not None else "",
                        ic_out_dir,
                        param.adjust_vma if param.adjust_vma is not None else ""
                        )
                    if (DEBUG): logD("command %s" % command, TAG)

                    ret = common.runCommand(command)
                    if ret == common.ERR_NONE:
                        if bootfile is not None and os.path.exists(bootfile):
                            shutil.copy(bootfile, ic_out_dir)

                        if certfile is not None and os.path.exists(certfile):
                            shutil.copy(certfile, ic_out_dir)
                    else:
                        msg = "Run ic script failed"
                        logE(msg, TAG)

                # all done, now, prepare output file
                if ret == common.ERR_NONE:
                    log(">> copy bin to output dir", TAG)
                    if (DEBUG): logD("ic_bin_dir %s --> ic_out_dir %s" %(ic_bin_dir,ic_out_dir), TAG)

                    for fname in os.listdir(ic_bin_dir):
                        f = os.path.join(ic_bin_dir, fname)
                        if os.path.isfile(f):
                            shutil.copy(f, ic_out_dir)

                    log(">> convert bin to srec", TAG)
                    for file in ifiles:
                        if (DEBUG): logD("file %s" % file, TAG)
                        name, ext = os.path.splitext(file)
                        
                        # in case of encryption, "_enc" will be added to end of file
                        suff = ""
                        if __req.is_enc and name.endswith(ENC_FILE_SUFFIX):
                            name_len = len(name) - len(ENC_FILE_SUFFIX)
                            name = name[0:name_len]
                            suff = ENC_FILE_SUFFIX
                        if (DEBUG): logD("name %s" % name, TAG)

                        binfile = os.path.join(ic_bin_dir, file)
                        srecfname = "%s%s.srec" % (name, suff)
                        srecfile = os.path.join(ic_out_dir, srecfname)
                        
                        vma_addr = None
                        srec_log = ""
                        if name in param.memory_map_dict:
                            map = param.memory_map_dict[name]
                            if map is None:
                                ret = common.ERR_FAILED
                                msg = "Not found map for %s" % name
                                break

                            # if vma_addr is set in memory map file, use it
                            # if not, use mem_addr
                            vma_addr = map.vma_addr if map.vma_addr is not None else map.mem_addr
                            srec_log = "Convert BIN %s to SREC %s, vma = %s (from memory map)" % (file, srecfname, vma_addr)
                        else:
                            vma_addr = param.adjust_vma if param.adjust_vma is not None else renesas_ic_param.DEFAULT_ADJUST_VMA
                            log("Not found %s in memory map, convert with default vma %s" % (name, vma_addr), TAG)
                            srec_log = "Convert BIN %s to SREC %s, vma = %s (default vma)" % (file, srecfname, vma_addr)
                        
                        command = "%s %s --input=%s --output=%s --target=srec --vma=%s" % (
                            bin_connvert_script, # sign script
                            "-v" if DEBUG else "",
                            binfile,
                            srecfile,
                            vma_addr
                        )
                        log("Convert %s to srec %s, vma %s" % (file, srecfname, vma_addr), TAG)
                        if (DEBUG): logD("command %s" % command, TAG)
                        ret = common.runCommand(command)
                        if (ret == common.ERR_NONE):
                            log_srec_convert += srec_log + ": OK \n"
                        else:
                            log_srec_convert += srec_log + ": FAILED \n"
                            msg = "Convert %s to srec failed" % file
                            logE(msg, TAG)
                            

                    log(">> convert cert bin to srec", TAG)
                    for file in outcertlist:
                        if (DEBUG): logD("file %s" % file, TAG)
                        fname = os.path.basename(file)
                        name, ext = os.path.splitext(fname)
    
                        suff = ""
                        # FIXME: currently, 
                        # if name.endswith(CERT_FILE_SUFFIX):
                        #     name_len = len(name) - len(CERT_FILE_SUFFIX)
                        #     name = name[0:name_len]
                        #     suff = CERT_FILE_SUFFIX
                        if (DEBUG): logD("name %s" % name, TAG)

                        vma_addr = None
                        # binfile = os.path.join(input_bin_dir, file)
                        srecfname = "%s%s.srec" % (name, suff)
                        srecfile = os.path.join(ic_out_dir, srecfname)
                        srec_log = ""
                        if name in param.memory_map_dict:
                            map = param.memory_map_dict[name]
                            if map is None:
                                ret = common.ERR_FAILED
                                msg = "Not found map for %s" % name
                                break
                            vma_addr = map.mem_addr
                            srec_log = "Convert cert BIN %s to SREC %s, vma = %s (from memory map)" % (fname, srecfname, vma_addr)
                        else:
                            vma_addr = param.adjust_vma if param.adjust_vma is not None else renesas_ic_param.DEFAULT_ADJUST_VMA
                            log("Not found %s in memory map, use default vma %s" % (name, vma_addr), TAG)
                            srec_log = "Convert cert  BIN %s to SREC %s, vma = %s (default vma)" % (fname, srecfname, vma_addr)

                        command = "%s %s --input=%s --output=%s --target=srec --vma=%s" % (
                            bin_connvert_script, # sign script
                            "-v" if DEBUG else "",
                            file,
                            srecfile,
                            vma_addr
                        )
                        log("Convert %s to srec %s, vma %s" % (file, srecfname, vma_addr), TAG)
                        if (DEBUG): logD("command %s" % command, TAG)
                        ret = common.runCommand(command)
                        if (ret == common.ERR_NONE):
                            log_srec_convert += srec_log + ": OK \n"
                        else:
                            log_srec_convert += srec_log + ": FAILED \n"
                            msg = "Convert %s to srec failed" % file
                            logE(msg, TAG)

                    log(">> copy memory_map")
                    if param.memory_map_dict is not None and len(param.memory_map_dict) > 0:
                        val = os.path.join(ic_out_dir, "memory_map")
                        with open(val, "w") as f:
                            for map in param.memory_map_dict.values():
                                f.write("%s %s %s %s %s\n" % (map.fname, map.target, map.mem_addr, map.flash_addr, map.vma_addr if map.vma_addr is not None else ""))
                    # if param.memory_map is not None and os.path.exists(param.memory_map):
                    #     if (DEBUG): logD("copy memory_map %s to out dir" % param.memory_map, TAG)
                    #     shutil.copy(param.memory_map, ic_out_dir)

                    filemapping = common.isValidString(__req.file_mapping)
                    if filemapping is not None:
                        log("copy file map")
                        val = os.path.join(ic_out_dir, "filemapping")
                        common.write_string_to_file(val, filemapping)

                    if len(log_srec_convert) > 0:
                        log("copy srec log")
                        val = os.path.join(ic_out_dir, "log_srec_convert")
                        common.write_string_to_file(val, log_srec_convert)

                log(">> Copy tbl file to image creator dir", TAG)
                if (DEBUG): logD("%s --> %s" % (input_tbl_dir,ic_out_dir), TAG)
                tbl_dir = os.path.join(ic_out_dir, "tbl")
                common.mkdir(tbl_dir)
                for fname in os.listdir(input_tbl_dir):
                    shutil.copy(os.path.join(input_tbl_dir, fname), tbl_dir)
                
                if ret == common.ERR_NONE and __req.saveParam:
                    log(">> Save param", TAG)
                    [ret, msg] = addNewParam(param, current_username())
                
                if ret == common.ERR_NONE:
                        resp = self.packOutput(__req, ic_out_dir)
                else:
                    resp = SignResp(__req, ret, msg)

            else:
                logE("Not sign any file", TAG)
                resp = SignResp(__req, common.ERR_NOT_FOUND, "Not file to sign")

        return resp

    # do signing
    def do_sign(self, __req):
        if (DEBUG): logD("Renesas do_sign", TAG)
        # check/prepare tool
        log("Prepare sign tool", TAG)
        [__code, __msg] = self.prepareTool(__req, RENESAS_SIGN_TOOL_ZIP_PATH)

        if (__code != common.ERR_NONE):
            return SignResp(__req, __code, __msg)

        # Get key basing on key id, or use default one
        log ("Prepare key: %s" % __req.key_id, TAG, True)

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
                # log("do_sign, use default key", TAG)
                __code = common.ERR_NOT_FOUND
                __msg = "Failed, no key is selected"
        
        if (__code == common.ERR_NONE and __req.root_key_info != None):
            [__code, __msg] = self.prepareKey(__req, __req.root_key_info, __req.key_dir, fnames=[ROOT_AES_KEY_FNAME])

        if (__code != common.ERR_NONE):
            applog.logE("Prepare key failed %d" % __code)
            return SignResp(__req, __code, __msg)
       
        log("Start generate signed firmware", TAG)
        return self.sign_firmware(__req)

    # Get template render for webpage used to manual sign
    def get_html_render_for_manual_sign(self, request):
        from server.key.key_mng import keyMgr
        from server.sign import signfactory as signfactory
        from server.sign.signrenesas import RENESAS_TOOL_NAME
        key_list = keyMgr().get_all_keys(tool=RENESAS_TOOL_NAME, keytool=RENESAS_KEY_CERT_TOOL_NAME)
        root_key_list = keyMgr().get_all_keys(tool=RENESAS_TOOL_NAME, keytool=RENESAS_ROOT_KEY_TOOL_NAME)
        params = getListParam()
        return render_template(
            "sign/sign_renesas_ic.html"
            # common for headers
            , login=is_login(request)
            , username=current_username()
            # common for sign
            , module="Renesas: Generate Signed Image (using image create)"
            , project_list=getProjectList()
            , model_list=getModelList()
            , key_list=key_list
            , default_key_id=common.DEFAULT_KEY_ID
            , root_key_list=root_key_list
            , default_root_key_id=common.DEFAULT_KEY_ID
            , none_root_key_id=common.NONE_KEY_ID
            , signtoolname=RENESAS_TOOL_NAME
            , toolname=RENESAS_IC_TOOL_NAME
            , rootkeytoolname=RENESAS_ROOT_KEY_TOOL_NAME
            , keytoolname=RENESAS_KEY_CERT_TOOL_NAME
            , boot_param_list=params.values() if params is not None else []
            , default_adjust_vma=renesas_ic_param.DEFAULT_ADJUST_VMA
            , default_platform=renesas_ic_param.PLATFORM_DEFAULT
            )


    # get tool list
    def getKeyToolList(self):
        return [RENESAS_KEY_CERT_TOOL_NAME, RENESAS_ROOT_KEY_TOOL_NAME, RENESAS_SB_KEY_TOOL_NAME]

    # get help, return html string or None on error
    def get_help(self, request):
        cmd_id = request.args.get('cmdid', default = None)
        paramid = request.args.get('paramid', default = None)
        ret = "Get help failed: Invalid information"
        if (DEBUG): logD("Get help", TAG)
        if (DEBUG): logD("cmd_id %s" % cmd_id, TAG)
        if (DEBUG): logD("paramid %s" % paramid, TAG)
        if cmd_id is not None:
            param = getParam(cmd_id)
            if param is not None:
                paramid = common.isValidString(paramid)
                if paramid is not None:
                    fpath = None
                    if paramid == renesas_ic_param.ITEM_MEMORY_MAP and common.isValidString(param.memory_map) is not None:
                        fpath = param.memory_map
                    elif paramid == renesas_ic_param.ITEM_BOOT_PARAM and common.isValidString(param.boot_param) is not None:
                        fpath = param.boot_param
                    elif paramid == renesas_ic_param.ITEM_CERT_PARAM and common.isValidString(param.cert_param) is not None:
                        fpath = param.cert_param
                    elif paramid == renesas_ic_param.ITEM_HELP and common.isValidString(param.help) is not None:
                        fpath = param.help
                    else:
                        logE("Invalid param id", TAG)

                    if (DEBUG): logD("fpath %s" % fpath, TAG)
                    if fpath is not None:
                        # read file
                        content = common.read_string_from_file(fpath)
                        
                        if common.isValidString(content) is not None:
                            return render_template(
                                "text.html"
                                , login=is_login(request)
                               , value = content
                                )
                        else:
                            ret = "Failed to read param info"
                            logE("Failed to read param info %s" % param.memory_map, TAG)
                    else:
                        ret = "Invalid paramid %s or file not exist" % paramid
                        logE(ret, TAG)
                else:
                    ret = ""
                    # read help and memory map, merge into one string to display
                    if common.isValidString(param.help):
                        help = common.read_string_from_file(param.help)
                        if help is not None:
                            ret += help
                        else:
                            ret += "Read help for %s failed" % cmd_id
                            logE("Read help for %s failed" % cmd_id, TAG)

                    if common.isValidString(param.memory_map):
                        map = common.read_string_from_file(param.memory_map)
                        if map is not None:
                            ret += "\n\n"
                            ret += "--------\n"
                            ret += "MEMORY MAP INFO:\n"
                            ret += map
                        else:
                            ret += "Read memory map for %s failed" % cmd_id
                            logE("Read memory map for %s failed" % cmd_id, TAG)
                    
                    if common.isValidString(ret) is not None:
                        return render_template(
                            "text.html"
                            , login=is_login(request)
                            , value = ret
                            )
                    else:
                        ret = "Failed to help"
                        logE("Failed to read help %s" % param.memory_map, TAG)
            else:
                ret = "invalid command id %s" % cmd_id
                logE(ret, TAG)
        else:
            ret = "invalid command id"
            logE(ret, TAG)
        return ret

    # get download file, return path file to download or None on error
    def get_download_file(self, request):
        cmd_id = request.args.get('cmdid', default = None)
        paramid = request.args.get('paramid', default = None)

        ret = None
        log("Get download file", TAG)

        if cmd_id is not None:
            log("cmd_id %s" % cmd_id, TAG)
            param = getParam(cmd_id)
            # get param corresponding with command id
            if param is not None: 
                paramid = common.isValidString(paramid)
                # which information do you want to get? (param id)
                if paramid is not None:
                    log("paramid %s" % paramid, TAG)
                    fpath = None

                    if paramid == renesas_ic_param.ITEM_BOOT_BIN and common.isValidString(param.boot_bin) is not None:
                        fpath = param.boot_bin
                    elif paramid == renesas_ic_param.ITEM_BOOT_PARAM and common.isValidString(param.boot_param) is not None:
                        fpath = param.boot_param
                    elif paramid == renesas_ic_param.ITEM_CERT_BIN and common.isValidString(param.cert_bin) is not None:
                        fpath = param.cert_bin
                    elif paramid == renesas_ic_param.ITEM_CERT_PARAM and common.isValidString(param.cert_param) is not None:
                        fpath = param.cert_param
                    else:
                        fpath = None
                        logE("not support to get download this param info", TAG)
                    
                    if (DEBUG): logD("fpath %s" % fpath, TAG)
                    ret = fpath
                else: # not param id, download all public data of command
                    from server.app import getRootDownloadDir
                    import tempfile

                    download_dir = os.path.join(getRootDownloadDir(), RENESAS_IC_TOOL_NAME, "param")
                    common.mkdir(download_dir)
                    zfname = common.normalize_fname(param.name)
                    zpath = os.path.join(download_dir, "%s.zip" % zfname)
                    if os.path.exists(zpath):
                        log("remote existing file %s " % zfname, TAG)
                        os.remove(zpath)

                    # copy all param bin/file to temp dir, then zip it
                    with tempfile.TemporaryDirectory() as tmpdirname:
                        path = os.path.join(tmpdirname, "boot_bin")
                        os.mkdir(path)
                        param.copyParam(param.boot_bin, path)

                        path = os.path.join(tmpdirname, "cert_bin")
                        os.mkdir(path)
                        param.copyParam(param.cert_bin, path)

                        param.copyParam(param.boot_param, tmpdirname)
                        param.copyParam(param.cert_param, tmpdirname)
                        param.copyParam(param.memory_map, tmpdirname)
                        param.copyParam(param.help, tmpdirname)


                        # param.copyParams(tmpdirname)
                        if not common.zipfolder(tmpdirname, zpath) or not os.path.exists(zpath):
                            logE("prepare zip download file failed", TAG)
                            ret = None
                        else:
                            ret = zpath
            else:
                logE("invalid command id %s" % cmd_id, TAG)
                ret = None
        else:
            ret = None
            logE("invalid command id", TAG)
        return ret