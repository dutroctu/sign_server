#!/usr/bin/env python
#
#  ENTRY FOR SERVER
#

import sys
import os
from server.applog import log
from server.applog import logE
from server.applog import logD
from server.applog import init_log
import socket
import time
# from server import common as common
from server import common
import atexit
import traceback
import json

PORT = 5000
DBPORT = 9999

TAG = "app"

ROOT_TEMP_DIRECTORY_NAME = ".tmp"
ROOT_DATA_DIRECTORY_NAME = ".data"

INPUT_DIRECTORY_NAME = ".input"
OUTPUT_DIRECTORY_NAME = ".output"
DOWNLOAD_DIRECTORY_NAME = ".download"
LOG_DIRECTORY_NAME = ".log"

DEFAULT_WAIT_TO_DELETE_MS = (60 * 60 * 1000) #

# ROOT_TEMP_DIRECTORY = os.path.join(ROOT_DIR, ROOT_TEMP_DIRECTORY_NAME)
# ROOT_DATA_DIRECTORY = os.path.join(ROOT_DIR, ROOT_DATA_DIRECTORY_NAME)

# #folder to store file received file from client
# INPUT_DIRECTORY = os.path.join(ROOT_TEMP_DIRECTORY, ".input")

# #folder to store output file
# OUTPUT_DIRECTORY = os.path.join(ROOT_TEMP_DIRECTORY, ".output")

# #folder to store file to be sent to client
# DOWNLOAD_DIRECTORY = os.path.join(ROOT_TEMP_DIRECTORY, ".download")

# list of support project
PROJECT_LIST = [
    # common.ANY_INFO,
    "tbox-boot",
    "tbox-provision",
    "tbox-remote",
    "tbox-eol",
    "tbox-cep",
    "mhu-boot",
    "mhu-provision",
    "mhu-remote",
    "mhu-eol",
    "fota",
    "androidapp",
    "androidpf",
    "androidota",
    ]

# list of model
MODEL_LIST = [
    # common.ANY_INFO,
    "vfe34-vn", #VN market
    "vfe34",
    "vf35",
    "SnS",
    ]

class AppConfig:
    projectList = PROJECT_LIST
    modelList = MODEL_LIST
    data_dir = ROOT_DATA_DIRECTORY_NAME
    temp_dir = ROOT_TEMP_DIRECTORY_NAME

    log_dir = None
    download_dir = None
    input_dir = None
    output_dir = None

    port = PORT
    dbport = DBPORT
    ip = ""
    last_start = ""
    cert_path = None
    cert_key_path = None
    dbName = ""
    auto_delete_time = 0

    def __init__(self):
        # log("ROOT_DIR %s" % ROOT_DIR)
        self.projectList = PROJECT_LIST
        self.modelList = MODEL_LIST
        self.data_dir = ROOT_DATA_DIRECTORY_NAME
        self.temp_dir = ROOT_TEMP_DIRECTORY_NAME

        self.log_dir = None
        self.download_dir = None
        self.input_dir = None
        self.output_dir = None

        self.port = 0
        self.dbport = 0
        self.ip = None
        self.last_start = common.current_time(common.TIME_FORMAT_TO_DISPLAY)
        self.dbName = ""
        self.auto_delete_time = 0

    
    def loadFile(self, path):
        log("Load app config from %s" % path)
        
        if path is not None and os.path.exists(path):
            jdata = common.read_string_from_file(path)
            if jdata is None or len(jdata) == 0:
                logE("no data in path %s" % path, TAG)
                ret = common.ERR_NO_DATA
            else:
                ret = self.fromJson(jdata)
        else:
            ret = common.ERR_INVALID_ARGS

        return ret

    def saveFile(self, path):
        log("Save app config to %s" % path)
        if path is not None:
            jdata = self.toJson()
            if jdata is not None:
                ret = common.write_string_to_file(path, self.toJson(), True)
            else:
                ret = common.ERR_FAILED
        else:
            ret = common.ERR_INVALID_ARGS
        return ret
    

    def toJson(self, indent=4):
        try:
            jdata = {
                "projectList":self.projectList if len(self.projectList) > 0 else "",
                "modelList":self.modelList if len(self.modelList) > 0 else "",
                "data_dir":self.data_dir if len(self.data_dir) > 0 else "",
                "temp_dir":self.temp_dir if len(self.temp_dir) > 0 else "",

                "log_dir":self.getLogPath(),
                "download_dir":self.getDownloadPath(),
                "input_dir":self.getInputPath(),
                "output_dir":self.getOutputPath(),
                
                "port":self.port if self.port > 0 else 0,
                "dbport":self.dbport if self.dbport > 0 else 0,
                "ip":self.ip if self.ip is not None and len(self.ip) > 0 else "",
                "last_start":self.last_start if len(self.last_start) > 0 else "",
                "dbName":self.dbName if len(self.dbName) > 0 else "",
                "auto_delete_time":self.auto_delete_time if self.auto_delete_time > 0 else 0,
                }
            jstring = json.dumps(jdata, indent=indent)
            return jstring
        except:
            traceback.print_exc()
            logE("Convert to json failed", TAG)
            return None

    def get_ip(self):
        return self.ip if self.ip is not None and len(self.ip) > 0 else common.get_ip()

    def get_port(self):
        return self.port if self.port > 0 else PORT

    def get_dbport(self):
        return self.dbport if self.dbport > 0 else DBPORT

    def get_auto_del_time(self):
        return self.auto_delete_time

    def getProjectList(self):
        return self.projectList

    def getModelList(self):
        return self.modelList

    def getDataPath(self, childPath = None):
        
        from server.app import ROOT_DIR
        path = self.data_dir
        if self.data_dir.startswith("/"):
            logD("getDataPath  %s" % data_dir)
            path =  self.data_dir if childPath is None else os.path.join(self.data_dir, childPath)
        else:
            logD("ROOT_DIR  %s" % ROOT_DIR)
            path = os.path.join(ROOT_DIR, self.data_dir) if childPath is None else os.path.join(ROOT_DIR, self.data_dir, childPath)
        return path

    def getTempPath(self, childPath = None):
        from server.app import ROOT_DIR
        path = self.temp_dir
        if self.temp_dir.startswith("/"):
            path =  self.temp_dir if childPath is None else os.path.join(self.temp_dir, childPath)
        else:
            path = os.path.join(ROOT_DIR, self.temp_dir) if childPath is None else os.path.join(ROOT_DIR, self.temp_dir, childPath)
        return path

    def getTempDownloadPath(self):
        return self.getTempPath(DOWNLOAD_DIRECTORY_NAME)

    def getTempLogPath(self):
        return self.getTempPath(LOG_DIRECTORY_NAME)

    def getTempInputPath(self):
        return self.getTempPath(INPUT_DIRECTORY_NAME)


    def getTempOutputPath(self):
        return self.getTempPath(OUTPUT_DIRECTORY_NAME)


    def getDownloadPath(self):
        if self.download_dir is not None and len(self.download_dir) > 0:
            return self.download_dir
        else:
            return self.getTempPath(DOWNLOAD_DIRECTORY_NAME)

    def getLogPath(self):
        if self.log_dir is not None and len(self.log_dir) > 0:
            return self.log_dir
        else:
            return self.getTempPath(LOG_DIRECTORY_NAME)

    def getInputPath(self):
        if self.input_dir is not None and len(self.input_dir) > 0:
            return self.input_dir
        else:
            return self.getTempPath(INPUT_DIRECTORY_NAME)


    def getOutputPath(self):
        if self.output_dir is not None and len(self.output_dir) > 0:
            return self.output_dir
        else:
            return self.getTempPath(OUTPUT_DIRECTORY_NAME)

    
    def fromJson(self, val):
        try:
            jdata = json.loads(val)
            self.data_dir = jdata["data_dir"] if "data_dir" in jdata else ROOT_DATA_DIRECTORY_NAME
            self.temp_dir = jdata["temp_dir"] if "temp_dir" in jdata else ROOT_TEMP_DIRECTORY_NAME


            self.log_dir = jdata["log_dir"] if (("log_dir" in jdata) and (len(jdata["log_dir"]) > 0)) else self.getTempLogPath()
            self.download_dir = jdata["download_dir"] if (("download_dir" in jdata) and (len(jdata["download_dir"]) > 0)) else self.getDownloadPath()
            self.input_dir = jdata["input_dir"] if (("input_dir" in jdata) and (len(jdata["input_dir"]) > 0)) else self.getInputPath()
            self.output_dir = jdata["output_dir"] if (("output_dir" in jdata) and (len(jdata["output_dir"]) > 0)) else self.getOutputPath()

            self.projectList = jdata["projectList"] if "projectList" in jdata else PROJECT_LIST
            self.modelList = jdata["modelList"] if "modelList" in jdata else MODEL_LIST
            self.port = jdata["port"] if "port" in jdata and jdata["port"] > 0 else 0
            self.dbport = jdata["dbport"] if "dbport" in jdata and jdata["dbport"] > 0 else 0
            self.ip = jdata["ip"] if "ip" in jdata and len(jdata["ip"]) > 0 else None
            self.dbName = jdata["dbName"] if "dbName" in jdata and len(jdata["dbName"]) > 0 else common.get_ip()
            self.auto_delete_time = jdata["auto_delete_time"] if "auto_delete_time" in jdata and jdata["auto_delete_time"] > 0 else 0

            for item in PROJECT_LIST:
                if item not in self.projectList:
                    self.projectList.append(item)
            
            for item in MODEL_LIST:
                if item not in self.modelList:
                    self.modelList.append(item)
            return common.ERR_NONE
        except:
            traceback.print_exc()
            logE("Parse from json failed %s " % val, TAG)
            return common.ERR_EXCEPTION
        

