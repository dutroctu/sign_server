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
from server.app import getRootDownloadDir
from server.app import KEEP_OUTPUT_FILE
from server.fota.fotagenresp import FotaGenResp
import os
from server import applog as applog 
from server.applog import log
from server.applog import logD
from server.applog import logE
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
from server.app import DEBUG
TAG = "fota"

# Common fota request
class FotaGenReq(object):
    access_token = "" # for log in feature
    model = ""
    project = ""
    zip_output = False # if output is zip file, instead of redirecting to download page

    in_working_folder = "" # caller's input data
    out_working_folder = "" # output data when doing signing
    tool_working_folder = "" # path to tool folder
    key_working_folder = "" # path to key dir

    file_list = {} # list of input file, dict of name (<input name=xxx>) and full path
    file_path_list = {} # list of input file, dict of name (<input name=xxx>) and full path
    ver_list = {} # version of each module
    zip_list = {} # file of each module is zip or not
    session = None # fota session
    key_type = None # TODO: change to use key_id, for user to select key for fota
    is_api = False # Is called via API
    key_id = INVALID_KEY_ID
    key_info = None
    def __init__(self, __request):
        # Parse request info
        self.key_type = request.form.get(common.PARAM_KEY_TYPE)
        self.project = request.form.get(common.PARAM_PROJECT)
        self.model = request.form.get(common.PARAM_MODEL)
        self.access_token = request.form.get(common.PARAM_ACCESS_TOKEN)
        
        # apis
        if common.PARAM_API in request.form:
            self.is_api = request.form.get(common.PARAM_API)

        # zip output
        zip = request.form.get(common.PARAM_ZIP_OUTPUT)

        self.zip_output = common.isZip(zip)

        if (DEBUG): logD("zip_output %s" %(self.zip_output))

        # generate session
        # TODO: generate here, but push other place, so risk of duplicateion session id
        # Re-use Session Management of Sign module
        from server.sign import signfactory
        self.session = signfactory.SignFactory.getSession() # WARNING: just create session, not manage by session management yet


        # check if key id is specified
        if common.PARAM_KEY_ID in request.form:
            self.key_id = request.form.get(common.PARAM_KEY_ID)
        else:
            key_name = common.extract_form_request(request, common.PARAM_KEY_NAME)
            if key_name is not None and len(key_name) > 0: #if key name, need to match with project and model
                if key_name == common.DEFAULT_KEY_ID:
                    self.key_id = key_name
                else:
                    self.key_info = keyMgr().get_key_by_name(key_name, project=self.project, model=self.model)
                    if (self.key_info is not None):
                        self.key_id = self.key_info.id
                    else:
                        self.key_id = INVALID_KEY_ID
            else:
                self.key_id = DEFAULT_KEY_ID

        # TODO: search default key in db
        if self.key_id == DEFAULT_KEY_ID:
            self.key_info = keyMgr().get_default_key(self.project, self.model, "fota", "fota")
            if self.key_info is None:
                log("Not found default key, use default in tool if exists")

        # make working folder for request
        import server.fota
        # input folder (i.e. uploaded file)
        self.in_working_folder = os.path.join(getRootInputDir(), self.session.uuid)
        # output folder
        self.out_working_folder = os.path.join(getRootOutputDir(), self.session.uuid)
        self.tool_working_folder = ""

        # save upload file to input fulder
        for key in request.files.keys():
            # key is module name

            # get list of file
            files = request.files.getlist(key)
            if (DEBUG): logD("file: %s has %s file" %(key, len(files)))
            self.file_list[key] = None
            for file in files:
                # check if file info is valid
                # if not file is selected to upload, files still not null, but its info is null
                if file is not None and file.filename is not None and len(file.filename) > 0:
                    if (files is not None and len(files) > 0):
                        self.file_list[key] = files # list of files of module (key)
                        break
            # get version of modules
            # TODO: check version
            version = request.form["ver_%s" % key]
            if (version is not None):
                self.ver_list[key] = version.strip()
            else:
                self.ver_list[key] = None

            # upload file is zip one or not
            # TODO: handle case multiple zip file is uploaded
            zip_name = "zip_%s" % key
            if zip_name in request.form:
                zipbin = request.form.get(zip_name)
            else:
                zipbin = False
            
            # TODO: just initialize handling, do handle it
            # TODO: handle the case that zip is selected, but it's not zip
            if (zipbin is not None):
                if (DEBUG): logD("%s zip %s" %(key, zipbin))
                self.zip_list[key] = True if zipbin == 'on' else False
            else:
                self.zip_list[key] = False

    def toString(self, isFull=False):
        str = ""
    
        if (self.session is not None):
            str += "session: %s, " % self.session.toString()
        if (isFull):
            if (self.model is not None):
                str += "model: %s, " % self.model
            if (self.access_token is not None):
                str += "access_token: %s, " % self.access_token
            if (self.in_working_folder is not None):
                str += "in_working_folder: %s, " % self.in_working_folder
            if (self.out_working_folder is not None):
                str += "out_working_folder: %s, " % self.out_working_folder
            if (self.ver_list is not None):
                str += "ver_list: %s, " % self.ver_list

        str += "\n"
        return str

    # clean up fota request data
    def clean(self):
        if (DEBUG): logD("SignRequest: remove in_working_folder %s" % self.in_working_folder)
        common.rmdirs(self.in_working_folder)
        if (DEBUG): logD("SignRequest: remove out_working_folder %s" % self.out_working_folder)
        common.rmdirs(self.out_working_folder)
        #download folder will be clean in SignResp
