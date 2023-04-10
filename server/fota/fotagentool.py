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
from server.app import ROOT_DIR
from server.app import getModelList
from server.app import getProjectList
from server.app import KEEP_OUTPUT_FILE
from server.fota.fotagenresp import FotaGenResp
from server.fota.fotagenreq import FotaGenReq
import os
from server import applog as applog 
import shutil
from server import common as common
import traceback
# import fota
import server.login

from server.common import DEFAULT_KEY_ID
from server.common import INVALID_KEY_ID
from server.storage import storageMgr
from server import database as database
from server.key.key_mng import keyMgr


from server.applog import log
from server.applog import logD
from server.applog import logE
import zipfile
import subprocess
from server.app import DEBUG
TAG = "fotatool"
# toolg for fota
TOOL_FOTA_FOLDER = os.path.join(ROOT_DIR, "tool/fota_tools")
TOOL_FOTA_FOLDER_ZIP = os.path.join(ROOT_DIR, "tool/fota_tools/fota_tools.zip")
# Signing tool

TOOL_FOTA_KEY_DIR_NAME = "integration_signing"
TOOL_FOTA_SIGN_SCRIPT_FNAME = "FOTAEncryptSigning.py"
TOOL_FOTA_SIGN_SCRIPT_REL_PATH = os.path.join(TOOL_FOTA_KEY_DIR_NAME, TOOL_FOTA_SIGN_SCRIPT_FNAME)

TOOL_FOTA_GEN_DIR_NAME = "fota_package_creator"
TOOL_FOTA_GEN_SCRIPT_FNAME = "make_fota_pkg.sh"

TOOL_FOTA_SIGN_SCRIPT = os.path.join(TOOL_FOTA_FOLDER, TOOL_FOTA_SIGN_SCRIPT_REL_PATH)
TOOL_FOTA_GEN_SCRIPT = os.path.join(TOOL_FOTA_FOLDER, TOOL_FOTA_GEN_DIR_NAME, TOOL_FOTA_GEN_SCRIPT_FNAME)


TOOL_FOTA_GEN_SCRIPT_REL_PATH = os.path.join(TOOL_FOTA_GEN_DIR_NAME, TOOL_FOTA_GEN_SCRIPT_FNAME)


# publi/private key
# TODO: secure them
TOOL_FOTA_PRIV_KEY_FNAME = "sign_private.pem"
TOOL_FOTA_PUB_KEY_FNAME = "fota_public.pem"

TOOL_FOTA_PRIV_KEY_REL_PATH = os.path.join(TOOL_FOTA_KEY_DIR_NAME, TOOL_FOTA_PRIV_KEY_FNAME)
TOOL_FOTA_PUB_KEY_REL_PATH = os.path.join(TOOL_FOTA_KEY_DIR_NAME, TOOL_FOTA_PUB_KEY_FNAME)

TOOL_FOTA_PRIV_KEY = os.path.join(TOOL_FOTA_FOLDER, TOOL_FOTA_PRIV_KEY_REL_PATH)
TOOL_FOTA_PUB_KEY = os.path.join(TOOL_FOTA_FOLDER, TOOL_FOTA_PUB_KEY_REL_PATH)


# OEM key
TOOL_FOTA_OEM_KEY_FNAME = "oemkey"
TOOL_FOTA_OEM_KEY_REL_PATH  = os.path.join(TOOL_FOTA_KEY_DIR_NAME, TOOL_FOTA_OEM_KEY_FNAME)
TOOL_FOTA_OEM_KEY = os.path.join(TOOL_FOTA_FOLDER, TOOL_FOTA_OEM_KEY_REL_PATH)

BINARY_PARAM = {
    "tbox":"-tbox_images",
    "xgw":"-xgw_images"
}
BINARY_VER_PARAM = {
    "tbox":"-tbox_ver",
    "xgw":"-xgw_ver"
}

OUT_FILE = "update.tar.bin"
# Common class for fota tool
class FotaTool(object):
    # parse request
    def parse_request(self, request):
        return FotaGenReq(request)
    
    def handle_error(self):
        pass

    # render html file to show on browser
    def get_html_render_for_manual_sign(self, __req):
        import server.fota
        from server.login.login import is_login
        from server.login.login import current_username
        return render_template(
            "fota.html"
            , login=is_login(request)
            , model_list=getModelList()
            , project_list=getProjectList()
            , key_type_list=server.fota.KEY_TYPE_LIST
            , module_list=server.fota.MODULE_LIST
            , username=current_username()
            )

    # check request info
    def check(self, __req):
        __result_str = ""
        __result_code = 0
        # TODO: re-work this
        import server.fota
        if __req.model is None or len(__req.model) == 0:
            __result_code = -1
            __result_str += "No model, "
        else :
            if __req.model not in getModelList():
                __result_code = -1
                __result_str += "model %s not support, " % (__req.model )

        if __req.key_type is None or len(__req.key_type) == 0:
            __result_code = -1
            __result_str += "No key type, "
        else :
            if __req.key_type not in server.fota.KEY_TYPE_LIST:
                __result_code = -1
                __result_str += "key_type %s not support, " % (__req.key_type )

        if __req.file_list is None or len(__req.file_list) == 0:
            __result_code = -1
            __result_str += "No file, "

        if (__result_code == 0):
            __result_str = "OK"

        return [__result_code, __result_str]

    # STEPS OF REQUEST PROCESSIONG: PREPARE -> DO SIGN/FOTA -> FINALIZE

    # do some preparation before signing
    def prepare(self, __req):
        if (DEBUG): logD("prepare: %s" % __req.toString())
        # check paramater
        [__code, __msg] = self.check(__req)

        if (__code != 0):
            return [__code, __msg]


        # make working folder for session
        common.mkdir(__req.in_working_folder)
        common.mkdir(__req.out_working_folder)

        # save upload file to input folder
        try:
            for key, files in __req.file_list.items() :
                if files is not None:
                    if (__req.ver_list[key] is None or len(__req.ver_list[key]) <= 0):
                        return [-1, "%s has no version" % key]
                    paths = ""
                    fdir = os.path.join(__req.in_working_folder, key)
                    iszip = False
                    # if it's zip file, extract it
                    # TODO: multiple zip file?
                    if (key in __req.zip_list and __req.zip_list[key] is True):
                        iszip = True
                        zfdir = os.path.join(fdir, "unzip")
                    
                    if (not os.path.exists(fdir)):
                        common.mkdir(fdir)
                    for file in files:
                        fname = common.normalize_fname(file.filename)
                        fpath = os.path.join(fdir, fname)
                        if (DEBUG): logD("save file to: %s" % fpath)
                        file.save(fpath)
                        if (iszip):
                            if fname.endswith("zip"): # TODO: suport tar, gz, etc.
                                unzip_res = common.unzip_file(fpath, zfdir)
                                if (unzip_res is False):
                                    return [-1, "Unzip %s failed" % fname]
                            else:
                                return [-1, "%s is not zip file" % fname]
                    if (iszip):
                        __req.file_path_list[key] = zfdir
                    else:
                        __req.file_path_list[key] = fdir
                else:
                    applog.logE("%s has no file" % key)
        except:
            traceback.print_exc()
            return [-1, "Failed to save uploaded files"]
        
        if (DEBUG): logD("file_path_list: %s" % __req.file_path_list)
        if (DEBUG): logD("ver_list: %s" % __req.ver_list)
        if (DEBUG): logD("zip_list: %s" % __req.zip_list)
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

    def prepareKey(self, __req, key_dir):
        # Get key basing on key id, or use default one
        log ("prepareKey: %s" % __req.key_id, TAG, True)
        ret = [common.ERR_FAILED, "Something wrong"]
        if (DEBUG): logD("key_dir %s" % key_dir)
        if (__req.key_id != common.DEFAULT_KEY_ID):
            from server.key.key_mng import keyMgr
            if __req.key_info is None:
                __req.key_info = keyMgr().get_key(__req.key_id)
            if (__req.key_info != None):
                try:
                    # COPY KEY DATA TO OUTPUT FOLDER.
                    # FIXME: SHOULD PROTECT/ENCRYPT IT?
                    # TODO: Need to make sure that new key is used, not default one
                    if (__req.key_info.data_type == database.key.KEY_DATA_TYPE_FILE):
                        if ((__req.key_info.files is not None and len(__req.key_info.files) > 0) or 
                            ((__req.key_info.fids is not None and len(__req.key_info.fids) > 0))):
                            if len(__req.key_info.fids) > 0:
                                for fname, fid in __req.key_info.fids.items():
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
                                ret = [common.ERR_NONE, ""]
                            elif len(__req.key_info.files) > 0:
                                for fname, fpath in __req.key_info.files.items():
                                    if (DEBUG): logD("Copy %s from %s to %s" % (fname, fpath, key_dir))
                                    from server.key.key_mng import keyMgr
                                    shutil.copy(keyMgr().get_full_key_path(fpath), key_dir)
                                ret = [common.ERR_NONE, ""]
                            else:
                                # return SignResp(__req, -1, "no key to sign")
                                ret = [common.ERR_NO_DATA, "no key to sign"]
                            if ret[0] == common.ERR_NONE:
                                __req.key_working_folder = key_dir
                        else:
                            # return SignResp(__req, -1, "Invalid key data")
                            ret = [common.ERR_INVALID_DATA, "Invalid key data"]
                    else:
                        # return SignResp(__req, -1, "Not suitable key")
                        ret = [common.ERR_INVALID_DATA, "Not suitable key"]
                except:
                    traceback.print_exc()
                    ret = [common.ERR_EXISTED, "Exception occur"]
            else:
                # return SignResp(__req, -1, "Invalid key id")
                ret = [common.ERR_INVALID_DATA, "Invalid key id"]
        else:
            ret = [common.ERR_NONE, ""]
            __req.key_working_folder = __req.tool_working_folder
        return ret

    # real work
    def do_gen(self, __req):

        # TODO: get key from keymanagmeent

        sign_script = os.path.join(__req.tool_working_folder, TOOL_FOTA_GEN_SCRIPT_REL_PATH)

        # get script to do fota
        if not os.path.exists(sign_script):
            applog.logE("%s not found" % sign_script, TAG, True)
            return FotaGenResp(__req, -1, "Not found script to sign")
        
        oem_key = os.path.join(__req.tool_working_folder, TOOL_FOTA_OEM_KEY_REL_PATH)

        # check oem key to do encrypt
        if not os.path.exists(oem_key):
            applog.logE("%s not found" % oem_key, TAG, True)
            return FotaGenResp(__req, -1, "Not found oemkey to sign")

        # if (INPUT_IMAGE_TAG not in __req.file_path_list):
        #     return SignResp(__req, -1, "Uploaded file required input type name is '%s'" % INPUT_IMAGE_TAG)

        # in_file = __req.file_path_list[INPUT_IMAGE_TAG]
        # sign_fname = __req.getSignFile(INPUT_IMAGE_TAG)
        # if (in_file is None) or not os.path.exists(in_file):
        #     return SignResp(__req, -1, "file not found")
        output_file = os.path.join(__req.out_working_folder, OUT_FILE)

        # python3.6 ../../$SIGN_TOOL_PATH/FOTAEncryptSigning.py --enc-aes-256-cbc -oemk ../../$SIGN_TOOL_PATH/oemkey \
        #                                    -inf ./XGW_$XGW_VER.bin.raw -o ./XGW_$XGW_VER.bin
        # python3.6 $SIGN_TOOL_PATH/FOTAEncryptSigning.py -oemk $SIGN_TOOL_PATH/oemkey \
        #                                                 -inf .output_gen/${FOTA_PACKAGE_NAME} \
        #                                                 -prk $SIGN_TOOL_PATH/sign_private.pem \
        #                                                 -pbk $SIGN_TOOL_PATH/fota_public.pem \
        #                                                 -o .output_gen/${FOTA_PACKAGE_ENC_NAME}
        # command to run
        # script 
        # if (__req.type == "encrypt"):
        #     command = "python3 %s --%s -oemk %s -inf %s -o %s" % \
        #         (TOOL_FOTA_SIGN_SCRIPT, __req.algo, TOOL_FOTA_OEM_KEY, in_file, output_file)
        # else :
        #     if (__req.type == "sign"):
        #         command = "python3 %s -oemk %s -inf %s -prk %s -pbk %s -o %s" % \
        #             (TOOL_FOTA_SIGN_SCRIPT, TOOL_FOTA_OEM_KEY, in_file, TOOL_FOTA_PRIV_KEY, TOOL_FOTA_PUB_KEY, output_file)
        #     else:
        #         return SignResp(__req, -1, "type not suport %s" % __req.type)
        command = "%s -tool_path %s -out_folder %s -out_file %s" % (sign_script, __req.tool_working_folder, __req.out_working_folder, output_file)
        for key in __req.file_path_list:
            command += " %s %s" % (BINARY_PARAM[key], __req.file_path_list[key])
            command += " %s %s" % (BINARY_VER_PARAM[key], __req.ver_list[key])

        applog.log ("command: " + command, TAG, True)
        # start fota command
        __res = os.system(command)
        if __res != 0 :
            applog.logE("Generate failed with command %s, res %d" % (command, __res), TAG, True)
            return FotaGenResp(__req, -1, "Generate FOTA failed %d" % __res)

        # check ouput folder
        if not os.path.exists(output_file):
            applog.logE("output %s not found" % output_file, TAG, True)
            return FotaGenResp(__req, -1, "Not found output")

        __resp = FotaGenResp(__req, 0, "OK")
        # copy file to download folder
        if (DEBUG): logD("copy_to_download from %s to %s" % (OUT_FILE, output_file))
        if __resp.copy_to_download(OUT_FILE, output_file):
            if (DEBUG): logD("set response data for session %s" % __req.session.uuid)
            __req.session.set_data(__resp) # all well
        else: # failed to copy
            applog.logE("Failed to copy %s" % output_file)
            __resp.set_response_msg(-2, "failed to copy file for download")
        
        return __resp

    # post steps to do signing
    def finish(self, resp):
        ret = False
        if (resp is not None):
            if (DEBUG): logD("do finish resp: %s" % resp.toString())
            from server.sign import signfactory
            ret = resp.finalize()
            
            if (ret): # all well, save session 
                signfactory.SignFactory.pushSession(resp.fota_req.session)
            else: # failed, clear data
                if (not KEEP_OUTPUT_FILE):
                    resp.clean()
                # clean up session
                signfactory.SignFactory.clearSession(resp.fota_req.session)

        return ret
    
    # do fota
    def gen_fota(self, __req):
        [__code, __msg] = self.prepare(__req) # prepare
        if (__code == 0):
            [__code, __msg] = self.prepareTool(__req, TOOL_FOTA_FOLDER_ZIP)
            if (__code != common.ERR_NONE):
                return FotaGenResp(__req, __code, __msg)


            # Get key basing on key id, or use default one
            log ("Sign with key: %s" % __req.key_id, TAG, True)
            
            key_dir = os.path.join(__req.tool_working_folder, TOOL_FOTA_KEY_DIR_NAME)
            if (__req.key_id != common.DEFAULT_KEY_ID):
                priv_key = os.path.join(key_dir, TOOL_FOTA_PRIV_KEY_FNAME)
                pub_key = os.path.join(key_dir, TOOL_FOTA_PUB_KEY_FNAME)

                if os.path.exists(priv_key):
                    if (DEBUG): logD("Remove existing one to create new one")
                    common.rmdirs(priv_key)
                
                if os.path.exists(pub_key):
                    if (DEBUG): logD("Remove existing one to create new one")
                    common.rmdirs(pub_key)
                
                [__code, __msg] = self.prepareKey(__req, key_dir)
            
            resp = self.do_gen(__req) # do signing
        else:
            resp = FotaGenResp(__req, -1, __msg)

        self.finish(resp) # finalize result
        return resp


    def clean(self,__req):
        if (DEBUG): logD("FotaTool: clean request %s" % __req.toString())
        __req.clean()
        # TODO: review this
