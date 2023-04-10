#!/usr/bin/env python
#
#  SIGN TBOX CEP
#
import json
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
from server.key.cep.cep_key_tool import CEP_PRIV_KEY_FNAME, CEP_TOOL_NAME
from server.key.key_api_handling import convertKeyInfoJson
from server.key.key_mng import get_keytool_list, keyMgr

from server.sign.signreq import SignRequest
from server.sign.signreq import SignTool
from server.sign import signfactory as signfactory

from server.app import getProjectList
from server.app import getModelList
from server.common import DEFAULT_KEY_ID
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

from server.key.quectel.sb_attest_key_tool import KEY_TOOL_NAME as ATTEST_KEY_TOOL_NAME
from server.key.quectel.sb_dm_key_tool import KEY_TOOL_NAME as DM_KEY_TOOL_NAME
from server.key.quectel.root_key_tool import KEY_TOOL_NAME as ROOT_KEY_TOOL_NAME
from server.app import DEBUG

#meta data
TAG="SignTBoxCEP"
TBOX_CEP_TOOL_NAME = "cep"
TBOX_CEP_TOOL_DESC = "Sign CEP signature for TBox firmware"

#tool for cep signing
TOOL_CEP_SIGN_NAME = "sign_fs"
TOOL_PUBKEY_EXTRACTOR_NAME = "pub_key_extractor"
TOOL_CEP_SIGN = os.path.join(ROOT_DIR, "tool/cep/sign_fs")
TOOL_PUBKEY_EXTRACTOR = os.path.join(ROOT_DIR, "tool/cep/pub_key_extractor")

#input file
INPUT_HASHLIST_TAG = "hashlist"

SIGN_TYPE_LIST = ["RootFS", "OEMApp"]

# Sign Request of Tbox
class SignRequestTboxCEP(SignRequest):
    sign_type = ""
    key_id = None
    key_info = None
    outfile = None
    def __init__(self, __request):
        super(SignRequestTboxCEP, self).__init__(__request, TBOX_CEP_TOOL_NAME)
        self.sign_type = request.form.get('sign_type')
        [self.key_id, self.key_info] = self.getKeyInfo(request, None, "target_key", CEP_TOOL_NAME)
        if self.sign_type == "OEMApp":
          self.outfile = "oem_sig_list.csv"
        else:
          self.outfile = "sig_list.csv" #__req.getSignFile(INPUT_HASHLIST_TAG)

class SignToolTBoxCEP(SignTool):
    def getName(self, desc=False):
        return TBOX_CEP_TOOL_NAME if not desc else TBOX_CEP_TOOL_DESC

    # parse request
    def parse_request(self, request):
        return SignRequestTboxCEP(request)

    def do_sign(self, __req):
        # hash file
        in_file = __req.file_path_list[INPUT_HASHLIST_TAG][0]
        if (in_file is None) or not os.path.exists(in_file):
            return SignResp(__req, -1, "file not found")

        logE("FILE %s" % in_file, TAG)
        
        if __req.sign_type == "OEMApp":
          sign_fname = "oem_sig_list.csv"
        else:
          sign_fname = "sig_list.csv" #__req.getSignFile(INPUT_HASHLIST_TAG)
        
        output_file = os.path.join(__req.out_working_folder, sign_fname)

        if not os.path.exists(TOOL_CEP_SIGN):
            logE("%s not found" % TOOL_CEP_SIGN, TAG, True)
            return SignResp(__req, -1, "Not found script to sign")
        
        tool_working_folder = os.path.join(__req.out_working_folder, "tool")
        common.mkdir(tool_working_folder)
        logD("TOOL WORKING %s" % tool_working_folder, TAG)
        #copy to tool_working folder
        common.copyFiles(TOOL_CEP_SIGN, tool_working_folder)
        _sign_script = os.path.join(tool_working_folder, TOOL_CEP_SIGN_NAME)
        logD("SIGN SCRIPT PATH %s" % _sign_script, TAG)
        key_dir = os.path.join(__req.out_working_folder, "key")
        if __req.key_info != None:
            if os.path.exists(key_dir):
                if (DEBUG): logD("Remove existing key_dir to create new one")
                common.rm_file_in_dir(key_dir)
            else:
                common.mkdir(key_dir)
            if (DEBUG): logD("Prepare key", TAG)
            [ret, __msg] = self.prepareKey(__req, __req.key_info, key_dir)
            if (ret == common.ERR_NONE):
                __req.key_working_folder = key_dir
            else:
                logE("Prepare key failed", TAG)
        else:
            logE("no key", TAG)
            return SignResp(__req, common.ERR_FAILED, "No Key")

        key_files = "%s/%s" % (__req.key_working_folder, CEP_PRIV_KEY_FNAME)
        logD(key_files, TAG)

        command = "%s sign -private_key_path %s --hash_list %s --sig_list %s" % (
            _sign_script, key_files, in_file, output_file) #TODO: change later
        
        log ("command: " + command, TAG, True)
        
        # start signing
        __res = os.system(command)
        if (DEBUG): logD("command %d" % __res)
        if __res != 0 :
            logE("Signed failed with command %s, res %d" % (command, __res), TAG, True)
            return SignResp(__req, -1, "Signed failed %d" % __res)

        # check result
        log("sign output file %s" % output_file, TAG, True) # output_file is full signed binaries, to be used by caller for next signing steps
        if not os.path.exists(output_file):
            logE("output %s not found" % output_file, TAG, True)
            return SignResp(__req, -1, "Not found output")
        
        resp = SignResp(__req, 0, "OK")

        if resp.copy_to_download(sign_fname, output_file):
            # well done, setup data to be response to caller
            __req.session.set_data(resp) # assume that session is already checked before this function
        else:
            resp.set_response_msg(-1, "Failed to generate download file")

        return resp

    def getKeyToolList(self):
        return [CEP_TOOL_NAME]

    def getPublicKey(self, __req):
      retObj = {
          "PUBLIC_EXPONENT":'',
          "PUBLIC_KEY":'',
          "PUBLIC_KEY_MODULUS":'',
      }
      key_dir = os.path.join(__req.out_working_folder, "key")
      if __req.key_info != None:
          if os.path.exists(key_dir):
              if (DEBUG): logD("Remove existing key_dir to create new one")
              common.rm_file_in_dir(key_dir)
          else:
              common.mkdir(key_dir)
          if (DEBUG): logD("Prepare key", TAG)
          [ret, __msg] = self.prepareKey(__req, __req.key_info, key_dir)
          if (ret == common.ERR_NONE):
              __req.key_working_folder = key_dir
          else:
              logE("Prepare key failed", TAG)
      else:
          logE("no key", TAG)
          return abort(400, 'No key') 

      private_key = "%s/%s" % (__req.key_working_folder, CEP_PRIV_KEY_FNAME)
      logD(private_key, TAG)
      cmd_exponent = '%s -t private %s | grep "Exponent in base64" -A 1 | sed -n 2p' % (TOOL_PUBKEY_EXTRACTOR, private_key)
      cmd_pubkey = '%s -t private %s | grep "Public key in base64" -A 1 | sed -n 2p' % (TOOL_PUBKEY_EXTRACTOR, private_key)
      cmd_modulus = '%s -t private %s | grep "Modulus in base64" -A 1 | sed -n 2p' % (TOOL_PUBKEY_EXTRACTOR, private_key)
      logD(cmd_exponent, TAG)
      logD(cmd_pubkey, TAG)
      logD(cmd_modulus, TAG)
      retObj['PUBLIC_EXPONENT'] = subprocess.getoutput(cmd_exponent)
      retObj['PUBLIC_KEY'] = subprocess.getoutput(cmd_pubkey)
      retObj['PUBLIC_KEY_MODULUS'] = subprocess.getoutput(cmd_modulus)
      return retObj

    # Get template render for webpage used to manual sign
    def get_html_render_for_manual_sign(self, request):
        key_list = keyMgr().get_all_keys(tool=None, keytool="cepkeytool")
        return render_template(
            "sign/sign_cep.html"
            , login=is_login(request)
            , module="TBOX CEP"
            , project_list=getProjectList()
            , model_list=getModelList()
            , sign_type_list = SIGN_TYPE_LIST
            , key_list = key_list
            )