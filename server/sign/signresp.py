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
from server.app import getRootDownloadDir
import os
from server import applog as applog 
from server import common as common
from server import hash as hash
import traceback
import shutil
from server.login.session import SessionData
from zipfile import ZipFile
from server.applog import logD
from server.applog import Log
from server.app import DEBUG
from server.app import getAutoDeleteTime
from server.monitor.system_monitor import SystemMonitor

TAG = "signresp"
log = Log(TAG)



# Common signing request, used by many modules
class SignResp(SessionData):
    zip_file = None # zip download folder and return to caller, if caller request, if not, re-direct to download page
    download_file_list = {} # list of file can be downloaded, include file name and full path
    download_working_folder = "" # folder to contain files caller can download
    sign_req = None
    resp_code = 0
    resp_msg = 0
    def __init__(self, sign_req, resp_code, msg):
        self.sign_req = sign_req
        self.resp_code = resp_code
        self.resp_msg = msg
        self.download_file_list = {}
        self.zip_file = None

        self.download_working_folder = os.path.join(getRootDownloadDir(), self.sign_req.session.uuid)

    # response message
    def set_response_msg(self, resp_code, msg = ""):
        self.resp_code = resp_code
        self.resp_msg = msg

    # copy file to download folder
    def copy_to_download(self, fname, file_path):
        log.i("copy_to_download from %s/%s to %s" %(fname, file_path, self.download_working_folder))
        if (not os.path.exists(self.download_working_folder)):
            common.mkdir(self.download_working_folder)
        # Auto delete
        if getAutoDeleteTime() > 0:
            SystemMonitor.addDeleteReq2Queue(self.download_working_folder, getAutoDeleteTime())
        
        if (os.path.exists(file_path)):
            try:
                shutil.copy(file_path, self.download_working_folder)
                real_fname = os.path.basename(file_path)
                copied_file = os.path.join(self.download_working_folder, real_fname)
                if (os.path.exists(copied_file)):
                    if (DEBUG): logD("Copy done, %s" %copied_file)
                    self.download_file_list[fname] = copied_file
                    return True
                else:
                    applog.logE("Copy file %s to %d failed" % (file_path, self.download_working_folder))
                    return False
            except:
                traceback.print_exc()
                return False
        else:
            return False

    # finalize response request, return True on  success
    def finalize(self):
        if (DEBUG): logD("SignResp: finalize")
        if (DEBUG): logD("download_file_list: %s" % self.download_file_list)
        ret = False
        
        if self.sign_req.output_resp:
            return True
        
        if (self.resp_code == 0):
            #generate hash
            checksum_filename = "signinfo"
            checksum_path = os.path.join(self.download_working_folder, checksum_filename)
            checksum_data = ""
            # checksum_data += "Sign Key:"
            keyinfos = self.sign_req.getListKeyInfo()
            if keyinfos is not None:
                for name,key_info in keyinfos.items():
                    if key_info is not None:
                        checksum_data += "%s: %s %s (id: %s)\n" % (
                            name,
                            key_info.name, 
                            "(default)" if key_info.isdefault else "",
                            key_info.id)
                    else:
                        checksum_data += "%s: default key from tool\n" % name
            else:
                checksum_data += "Key: default key from tool\n"

            checksum_data += "Project: %s\n" % self.sign_req.project
            checksum_data += "Model: %s\n" % self.sign_req.model
            checksum_data += "Tool: %s\n" % self.sign_req.tool

            signinfos = self.sign_req.getSignInfo()
            if signinfos is not None and len(signinfos) > 0:
                for key,value in signinfos.items():
                    checksum_data += "%s: %s\n" % (key, value)

            if (len(self.download_file_list) > 0):
                calcHash = True
                # generate hash of each file in download folder
                for key, file in self.download_file_list.items():
                    if (DEBUG): logD("%s: %s" % (key, file))
                    if (len(key) > 0 and os.path.exists(file)):
                        hashfile = hash.md5file(file)
                        if (hashfile is not None):
                            checksum_data += "%s: %s\n" %(key, hashfile)
                        else:
                            applog.logE("Generate hash for %s failed" % file)
                            calcHash = False
                            break
                    else:
                        applog.logE("file %s is not available to generate hash" % file)
                        calcHash = False
                        break

                if (calcHash):
                    if common.write_to_file(checksum_path, bytes(checksum_data, 'utf-8')):
                        self.download_file_list[checksum_filename] = checksum_path

                        # compress download folder to zip file
                        if (self.sign_req.zip_output):
                            self.zip_file = os.path.join(self.download_working_folder, "%s.zip" % self.sign_req.project)
                            if common.zipfolder(self.download_working_folder, self.zip_file):
                                ret = True # ok
                            else:
                                ret = False
                                self.resp_code = -1
                                self.resp_msg = "Generate zip failed"
                        else:
                            if (DEBUG): logD("not need to generate zip file")
                            ret = True # ok
                    else: # save md5 failed
                        applog.logE("Saved md5 %s failed" % checksum_path)
                        ret = False
                        self.resp_code = -1
                        self.resp_msg = "Saved md5 file failed"
                else: # calc md5 failed
                    ret = False
                    self.resp_code = -1
                    self.resp_msg = "Calculate md5 for output file failed"
            else:
                ret = False
                self.resp_code = -1
                self.resp_msg = "Nothing to return"
        else:
            # do nothing
            ret = False
        return ret

    def toString(self, isFull = False):
        str = ""
        str += "resp_code: %d, " % self.resp_code
        str += "resp_msg: %s, " % self.resp_msg
        if isFull:
            if (self.sign_req is not None):
                str += "sign_req: %s, " % self.sign_req.toString(isFull)
            if (self.zip_file is not None):
                str += "zip_file: %s, " % self.zip_file
            if (self.download_file_list is not None):
                str += "download_file_list: %s, " % self.download_file_list
            if (self.download_working_folder is not None):
                str += "download_working_folder: %s, " % self.download_working_folder
        str += "\n"
        return str
    
    # clean response
    def clean(self):
        if (DEBUG): logD("SignResp: clean data, download_working_folder %s" % self.download_working_folder)
        common.rmdirs(self.download_working_folder)
