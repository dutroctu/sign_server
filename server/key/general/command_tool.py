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
from server import key as key
import traceback
from server import common as common
from server.database.key_info import KeyInfo
from flask_login import login_required
from server.common import extract_form_request
from server.common import getJsonObjData

from server.key.key_mng import keyMgr
from server.key.key_tool import KeyRequest
from server.key.key_tool import KeyTool
import json
import zipfile
from io import BytesIO
import shutil

from server.storage.storage_mgr import storageMgr

TAG="commandtool"

GENKEY_TOOL_NAME = "commandtool"

COMMAND_TYPE_GEN_KEY="genkey"
COMMAND_TYPE_GEN_CERT="gencert"
COMMAND_TYPE_GEN_DATA="gendata"

COMMAND_TYPE_LIST=[COMMAND_TYPE_GEN_KEY, COMMAND_TYPE_GEN_CERT, COMMAND_TYPE_GEN_DATA]

ITEM_COMMAND_LIST = "commandlist"
ITEM_TYPE = "type"
ITEM_ID = "id"
ITEM_NAME = "name"
ITEM_HELP = "help"
ITEM_FILE = "file"
ITEM_PARAM = "params"
ITEM_SCRIPT = "script"
ITEM_COMMAND = "command"

COMMAND_LIST_FNAME = "commandlist.json"
COMMAND_DIR_PATH = os.path.join(getRootToolDir(), "openssl")
COMMAND_LIST_PATH = os.path.join(COMMAND_DIR_PATH, COMMAND_LIST_FNAME)

PARAM_KEY_DIR="KEY_DIR"
PARAM_IN_DIR="IN_DIR"
PARAM_IN_FILE="IN_FILE"
PARAM_IN_TEXT="IN_TEXT"
PARAM_IN_PREFIX="IN_PREFIX"
PARAM_PASS_ENV="PASS_ENV"
PARAM_WORK_DIR="WORK_DIR"
PARAM_OUT_PREFIX="OUT_PREFIX"
PARAM_OUT_DIR="OUT_DIR"
PARAM_PUB_OUT_DIR="PUB_OUT_DIR"
PARAM_IN_NAME="IN_NAME"
PARAM_SIZE="SIZE"

# Common command
class Command:
    type = None #type (genkey, gendata)
    id = None # id of command
    name = None # name of command
    help = None # help id of command
    file = None # script files (if zipfile, will be extracted when using)
    script = None # script to be run
    params = [] # list of paramaters name
    command = None # command to run (argument part only)

    def __init__(self, jobj):
        self.type = None
        self.id = None
        self.name = None
        self.help = None
        self.file = None
        self.script = None
        self.command = None
        self.params = []

        if jobj is not None:
            self.fromJsonObj(jobj)


    def fromJsonObj(self, jobj):
        self.type = getJsonObjData(jobj=jobj, name=ITEM_TYPE, default=None)
        self.name = getJsonObjData(jobj=jobj, name=ITEM_NAME, default=None)
        self.id = getJsonObjData(jobj=jobj, name=ITEM_ID, default=None)
        self.help = getJsonObjData(jobj=jobj, name=ITEM_HELP, default=None)
        self.file = getJsonObjData(jobj=jobj, name=ITEM_FILE, default=None)
        self.script = getJsonObjData(jobj=jobj, name=ITEM_SCRIPT, default=None)
        self.params = getJsonObjData(jobj=jobj, name=ITEM_PARAM, default=[])
        self.command = getJsonObjData(jobj=jobj, name=ITEM_COMMAND, default=None)

    def validate(self):
        if self.type is None or self.type not in COMMAND_TYPE_LIST:
            return [common.ERR_INVALID_ARGS, "invalid type"]

        
        if self.name is None or len(self.name) == 0:
            return [common.ERR_INVALID_ARGS, "invalid name"]
        
        if self.file is None or len(self.file) == 0:
            return [common.ERR_INVALID_ARGS, "invalid file"]

        if self.script is None or len(self.script) == 0:
            return [common.ERR_INVALID_ARGS, "invalid script"]

        if self.command is None or len(self.command) == 0:
            return [common.ERR_INVALID_ARGS, "invalid command"]

        return [common.ERR_NONE, "OK"]

    def toString(self):
        retstr = ""
        retstr += "type: %s,\n" % self.type
        retstr += "id: %s,\n" % self.id
        retstr += "name: %s,\n" % self.name
        retstr += "script: %s,\n" % self.script
        retstr += "command: %s,\n" % self.command
        retstr += "params: %s,\n" % str(self.params)
        return retstr

#
# Parst commandlist file to get list of supported command
# - type: type of commands (genkey, gendata), None mean any type
#
def getListCommand(type=None):
    if (DEBUG): logD("getListCommand, type %s" % type, TAG)
    commands = {}
    if (DEBUG): logD("list file %s" % COMMAND_LIST_PATH, TAG)
    if os.path.exists(COMMAND_LIST_PATH):
        try:
            with open(COMMAND_LIST_PATH) as jf: # parse json file
                jdata = json.load(jf)
                if (DEBUG): logD("jdata %s" % jdata, TAG)
                # parse each json object
                jcommandlist = getJsonObjData(jobj=jdata, name=ITEM_COMMAND_LIST, default=[])
                if jcommandlist is not None and len(jcommandlist) > 0:
                    for jcommand in jcommandlist:
                        command = Command(jcommand)
                        if (DEBUG): logD("command %s" % command.toString(), TAG)
                        if (type is None or command.type == type):
                            [ret, msg] = command.validate() # validate if data is valid
                            if (DEBUG): logD("command validate %d %s" % (ret, msg), TAG)
                            if ret == common.ERR_NONE:
                                commands[command.id] = command
                            else:
                                logE("Invalid command info, ret %d. %s" % (ret, msg), TAG)
                                commands={}
                                break
                else:
                    logE("Not found any command", TAG)
        except:
            traceback.print_exc()
            commands={}

    else:
        logE("Commandlist path not found", TAG)

    if (DEBUG): logD("commands %s" % str(commands.keys()), TAG)
    return commands

#
# Get command object basing on id
# - id: command id
# - type: type of command, None mean any type
#
def getCommand(id, type=None):
    if (DEBUG): logD("getCommand id %s, type %s" % (id, type), TAG)
    commands = getListCommand(type)
    if commands is not None and len(commands) > 0:
        if id in commands:
            return commands[id]
        else:
            logE("command id %s not found" % id, TAG)
            return None
    logE("No command list", TAG)
    return None
    
#
# Prepare command to before using
#
def prepareCommandTool(command, workdir):
    if (DEBUG): logD("prepareCommandTool command %s, workdir %s" % (command, workdir), TAG)
    if workdir is not None and os.path.exists(workdir):
        file = os.path.join(COMMAND_DIR_PATH, command.file)
        if (DEBUG): logD("file %s" % file, TAG)
        if os.path.exists(file):
            if common.isZipFile(file): # extract zip file if it's zip, else just copy
                command.unzip_file(file, workdir)
            else:
                shutil.copy(file, workdir)
            return [common.ERR_NONE, "OK"]
        else:
            logE("file %s not exist" % file, TAG)
            return [common.ERR_NOT_EXIST, "file not exist"]
    else:
        logE("work dir %s not exist" % workdir, TAG)
        return [common.ERR_NOT_EXIST, "folder not exist"]
    

#
# Make param string
#
def getParam(command, params={}):
    if (DEBUG): logD("getParam command %s, params %s" % (command, params), TAG)
    if command.command is not None:
        paramstr = command.command
        if (DEBUG): logD("param 1 %s" % paramstr, TAG)
        no_param = len(command.params)
        count = 0
        if (DEBUG): logD("no_param %d"  % no_param, TAG)

        # replace value of param in params param to command string
        while count < no_param :
            name = command.params[count]

            if (DEBUG): logD("count %d, name %s" % (count, name))

            # replace command indicator with real value
            paramstr = paramstr.replace("[[%d]]" % count, str(params[name]) if (name in params and params[name] is not None) else "")

            if (DEBUG): logD("paramstr: %s" % paramstr, TAG)
            count += 1

        log("param 2 %s" % paramstr, TAG)
        return paramstr
    else:
        log("No param", TAG)
        return ""
    
