#!/usr/bin/env python
#
#  SIGN FOT TBOX
#
import shutil
from server import common as common
from server.app import app
from server.app import DEBUG

import os
from server import applog as applog 
from server.applog import log
from server.applog import logD
from server.applog import logE
from datetime import datetime

from server import common as common
from server.common import DEFAULT as DEFAULT
from server import hash as hash

import traceback
import sys
import json

from server.sign import signfactory as signfactory

from server.app import getRootToolDir
from server.key.renesas.key_cert_tool import RENESAS_TOOL_DIR_NAME

from threading import Lock
from server.app import DEBUG
TAG = "renesas_ic_param"


# Prebuilt param list file name
PARAM_LIST_FNAME = "paramlist.json"
# Custome param list file name
CUSTOM_PARAM_LIST_FNAME = "custom_paramlist.json"

# Param list related files are located in tool dir > renesas tools > param
PARAM_DIR_NAME = "param"
PARAM_DIR_PATH = os.path.join(getRootToolDir(), RENESAS_TOOL_DIR_NAME, PARAM_DIR_NAME)
PARAM_LIST_PATH = os.path.join(PARAM_DIR_PATH, PARAM_LIST_FNAME)
CUSTOM_PARAM_LIST_PATH = os.path.join(PARAM_DIR_PATH, CUSTOM_PARAM_LIST_FNAME)

# Param inform in param list file is in json format, i.e. 
# {
#   "paramlist": [
#     {
#         "id": "firmware_param_b3", 
#         "name": "Paramber for B3 flashwriter", 
#         "boot_bin": "b3/bootrom_param.bin",
#         "boot_param": "b3/bootparam_image_SA0.txt", 
#         "cert_bin": "b3/cert_header_binary.zip", 
#         "cert_param": "b3/cert_header_image_SA6.txt", 
#         "default": true, 
#         "binary_type": "firmware", 
#         "help": "b3/help", 
#         "memory_map": "b3/memory_map.txt", 
#         "adjust_vma": "0xE6320000", 
#         "source": "prebuilt", 
#         "platform": "rcarh3", 
#         "last_update": ""
#     },
#     {
#       .... 
#     }
#   ]
# }

ITEM_PARAM_LIST = "paramlist"
ITEM_ID = "id"
ITEM_NAME = "name"
ITEM_BOOT_BIN = "boot_bin"
ITEM_BOOT_PARAM = "boot_param"
ITEM_CERT_BIN = "cert_bin"
ITEM_CERT_PARAM = "cert_param"
ITEM_DEFAULT = "default"
ITEM_BIN_TYPE = "binary_type"
ITEM_HELP = "help"
ITEM_MEMORY_MAP = "memory_map"
ITEM_ADJUST_VMA = "adjust_vma"
ITEM_SOURCE = "source"
ITEM_LAST_UPDATE = "last_update"
ITEM_PLATFORM = "platform"

# Request param
PARAM_CUSTOM_BOOT_FILE = "custom_boot_file"
PARAM_CUSTOM_CERT_FILE = "custom_cert_file"

# default VAM
DEFAULT_ADJUST_VMA="0xE6320000"

SOURCE_PREBUILT="prebuilt"

PLATFORM_RCARH3="rcarh3"
PLATFORM_DEFAULT=PLATFORM_RCARH3

ENCRYPTION_MODE_DISABLE=1
ENCRYPTION_MODE_ENABLE_NO_IV=2
ENCRYPTION_MODE_ENABLE_WITH_IV=3

###################################################################
# Memory
###################################################################
class MemoryMap:
    fname = None # file name, without extension
    target = None # target part, i.e. bl2, bl3
    mem_addr = None # memory address to load
    flash_addr = None # flash address to write
    vma_addr = None # vma address to srec convert

    def __init__(self):
        self.fname = None
        self.target = None
        self.mem_addr = None
        self.flash_addr = None
        self.vma_addr = None
    
    def toString(self):
        strval = ""
        strval += "fname: %s;" % self.fname if self.fname is not None else ""
        strval += "target: %s;" % self.target if self.target is not None else ""
        strval += "mem_addr: %s;" % self.mem_addr if self.mem_addr is not None else ""
        strval += "flash_addr: %s;" % self.flash_addr if self.flash_addr is not None else ""
        strval += "vma_addr: %s;" % self.vma_addr if self.vma_addr is not None else ""
        return strval

    def __str__(self):
        return self.toString()

###################################################################
# Parameters
###################################################################
class Param:
    id = None # id of command
    name = None # name of command
    boot_bin = None # Path to prebuilt boot param binaries (i.e. bootrom_param.bin)
    boot_param = None # Path to boot param (i.e. bootparam_image_SA0.txt)
    cert_bin = None # Path to prebuilt cert header binaries (i.e. bl31_start_address.bin)
    cert_param = None # Path to cert param file (i.e. cert_header_image_SA6.txt)
    help = None # Path to help/description file
    binary_type = None # Type of binaries ("firmware" for normal firmware, "flashwriter" for flash writer)
    memory_map = None # Path to memory map file
    adjust_vma = None # VMA adjustment when converting to srec and vice versa
    isdefault = False # default param or not
    memory_map_dict = {} # memory map dictionary, parsed from memory map file
    boot_param_dict = None # boot param dictionary
    cert_param_dict = None # cert param dictionary
    source = None # source of param, prebuilt or custome (added new)
    last_update = None # last update time
    platform = None # last update time

    def __init__(self, jobj=None):
        self.id = None
        self.name = None
        self.boot_bin = None
        self.boot_param = None
        self.cert_bin = None
        self.cert_param = None
        self.help = None
        self.binary_type = None
        self.memory_map = None
        self.adjust_vma = DEFAULT_ADJUST_VMA
        self.isdefault = False
        self.memory_map_dict = {}
        self.boot_param_dict = None
        self.cert_param_dict = None
        self.source = None
        self.last_update = None
        self.platform = None

        if jobj is not None:
            self.fromJsonObj(jobj)

    # Clone to new param information
    def clone(self):
        param = Param()
        param.id = self.id
        param.name = self.name
        param.boot_bin = self.boot_bin
        param.boot_param = self.boot_param
        param.cert_bin = self.cert_bin
        param.cert_param = self.cert_param
        param.help = self.help
        param.binary_type = self.binary_type
        param.memory_map = self.memory_map
        param.adjust_vma = self.adjust_vma
        param.isdefault = False
        # TODO: should clone memory map/param dictionary???
        param.memory_map_dict = self.memory_map_dict.copy() if self.memory_map_dict is not None else None
        # param.boot_param_dict = self.boot_param_dict
        # param.cert_param_dict = self.cert_param_dict
        param.source = self.source
        param.platform = self.platform

        return param

    # Convert from json, change relative path to full path
    def fromJsonObj(self, jobj):
        if (DEBUG): logD("fromJson", TAG)

        self.id = common.getJsonObjData(jobj=jobj, name=ITEM_ID, default=None)
        self.name = common.getJsonObjData(jobj=jobj, name=ITEM_NAME, default=None)

        # path to boot param binaries
        val = common.getJsonObjData(jobj=jobj, name=ITEM_BOOT_BIN, default=None)
        val = common.isValidString(val)
        if val is not None:
            self.boot_bin = self.get_param_fpath(val)

        # path to boot param definition
        val = common.getJsonObjData(jobj=jobj, name=ITEM_BOOT_PARAM, default=None)
        val = common.isValidString(val)
        if val is not None:
            self.boot_param = self.get_param_fpath(val)
        
        # path to cert header binaries
        val = common.getJsonObjData(jobj=jobj, name=ITEM_CERT_BIN, default=None)
        val = common.isValidString(val)
        if val is not None:
            self.cert_bin = self.get_param_fpath(val)

        # path to cert param definition
        val = common.getJsonObjData(jobj=jobj, name=ITEM_CERT_PARAM, default=None)
        val = common.isValidString(val)
        if val is not None:
            self.cert_param = self.get_param_fpath(val)

        # path to help file
        val = common.getJsonObjData(jobj=jobj, name=ITEM_HELP, default=None)
        val = common.isValidString(val)
        if val is not None:
            self.help = self.get_param_fpath(val)
        
        # Source of param
        self.source = common.getJsonObjData(jobj=jobj, name=ITEM_SOURCE, default=None)

        # path to memory map file 
        val = common.getJsonObjData(jobj=jobj, name=ITEM_MEMORY_MAP, default=None)
        val = common.isValidString(val)
        if val is not None:
            self.memory_map = self.get_param_fpath(val)

        self.adjust_vma = common.getJsonObjData(jobj=jobj, name=ITEM_ADJUST_VMA, default=None)
        self.isdefault = common.getJsonObjData(jobj=jobj, name=ITEM_DEFAULT, default=False)

        # binary type
        self.binary_type = common.getJsonObjData(jobj=jobj, name=ITEM_BIN_TYPE, default=None)

        self.last_update = common.getJsonObjData(jobj=jobj, name=ITEM_LAST_UPDATE, default=None)
        self.platform = common.getJsonObjData(jobj=jobj, name=ITEM_PLATFORM, default=None)
    
    # convert ot json object, return json object or None if failed
    def toJsonObj(self):
        if (DEBUG): logD("toJsonObj", TAG)
        try:
            jdata = {
                ITEM_ID:self.id.strip() if common.isValidString(self.id) is not None else "",
                ITEM_NAME:self.name.strip() if common.isValidString(self.name) is not None else "",
                ITEM_BOOT_BIN:self.boot_bin.strip() if common.isValidString(self.boot_bin) is not None else "",
                ITEM_BOOT_PARAM:self.boot_param.strip() if common.isValidString(self.boot_param) is not None else "",
                ITEM_CERT_BIN:self.cert_bin.strip() if common.isValidString(self.cert_bin) is not None else "",
                ITEM_CERT_PARAM:self.cert_param.strip() if common.isValidString(self.cert_param) is not None else "",
                ITEM_DEFAULT:self.isdefault,
                ITEM_BIN_TYPE:self.binary_type.strip() if common.isValidString(self.binary_type) is not None else "",
                ITEM_HELP:self.help.strip() if common.isValidString(self.help) is not None else "",
                ITEM_MEMORY_MAP:self.memory_map.strip() if common.isValidString(self.memory_map) is not None else "",
                ITEM_ADJUST_VMA:self.adjust_vma.strip() if common.isValidString(self.adjust_vma) is not None else "",
                ITEM_SOURCE:self.source.strip() if common.isValidString(self.source) is not None else "",
                ITEM_LAST_UPDATE:self.last_update.strip() if common.isValidString(self.last_update) is not None else "",
                ITEM_PLATFORM:self.platform.strip() if common.isValidString(self.platform) is not None else "",
                }
            return jdata
        except:
            traceback.print_exc()
            logE("Convert param to json failed", TAG)
            return None
    
    # conver tto jsone string, None if error
    def toJson(self):
        if (DEBUG): logD("toJson", TAG)
        jdata = self.toJsonObj()
        if jdata is not None:
            return json.dumps(jdata)
        else:
            return None

    # validate, return [error code, error message]
    def validate(self):
        
        if self.id is None or len(self.id) == 0:
            return [common.ERR_INVALID_ARGS, "invalid id"]

        if self.name is None or len(self.name) == 0:
            return [common.ERR_INVALID_ARGS, "invalid name"]

        if self.binary_type is None or len(self.binary_type) == 0 or (self.binary_type != common.FIRMWARE and self.binary_type != common.FLASHWRITER):
            return [common.ERR_INVALID_ARGS, "invalid binary type"]

        if self.memory_map is None or len(self.memory_map) == 0:
            return [common.ERR_INVALID_ARGS, "invalid memory_map"]

        return [common.ERR_NONE, "OK"]

    def toString(self):
        retstr = ""
        retstr += "id: %s,\n" % self.id
        retstr += "name: %s,\n" % self.name
        retstr += "boot_bin: %s,\n" % self.boot_bin
        retstr += "cert_bin: %s,\n" % self.cert_bin
        retstr += "memory_map: %s,\n" % self.memory_map
        retstr += "isdefault: %d,\n" % self.isdefault
        retstr += "binary_type: %s,\n" % self.binary_type
        retstr += "adjust_vma: %s,\n" % self.adjust_vma
        retstr += "platform: %s,\n" % self.platform
        return retstr

    # Parase parameter, return parameter dictionary, or None if failed
    # dictionary: key is filename, value is address
    # file: Parameter file
    # Parameter file has same format, in text file, and each line:
    #      < filename > <address in hex>
    def parseParam(self, file):
        log("parseParam file %s" % file, TAG)
        if os.path.exists(file):
            try:
                content = None
                # read each line
                with open(file, "r") as f:
                    content = f.readlines()

                params = {}
                if content is not None and len(content) > 0:
                    for line in content:
                        if (DEBUG): logD("line %s" % line, TAG)
                        line = line.strip()
                        # ignore empty line or comment line (start with #)
                        if len(line) == 0 or line.startswith("#"):
                            continue
                        # split space
                        items = line.split()
                        if items is not None and len(items) > 1:
                            # <fname> <address>
                            fname = common.isValidString(items[0])
                            addr = common.isValidString(items[1])
                            # TODO: validate address format (hex string)
                            # temporary ignore, let Renesas tool check it later... is it ok????
                            # it'll took resource, but... forget it :-)
                            if fname is not None and addr is not None:
                                params[fname] = addr
                            else:
                                logE("Parse param failed, invalid line %s" % line, TAG)
                                return None
                        else:
                            logE("Parse param failed, invalid line %s" % line, TAG)
                            return None
                    
                    if (DEBUG): logD("params %s" % str(params), TAG)
                    return params
                else:
                    if (DEBUG): logD("empty file", TAG)
                
                if (DEBUG): logD("params %s" % str(params), TAG)
                return params 
            except:
                traceback.print_exc()
                logE("parase param failed, execption", TAG)
                return None
        else:
            logE("Parse param failed, file not exist", TAG)
            return None

    # get full path of files from relative path
    def get_param_fpath(self, val):
        if (DEBUG): logD("get_param_fpath %s" % val, TAG)
        if common.isValidString(val) is not None:
            return os.path.join(PARAM_DIR_PATH, val)
        return val

    # copy param file to garget binaries
    def copyParam(self, param, target_dir):
        if (DEBUG): logD("copyParam %s" % param, TAG)
        if (DEBUG): logD("target_dir %s" % target_dir, TAG)
        if common.isValidString(param) is not None:
            return common.copyFiles(param, target_dir)
        else:
            return common.ERR_NONE

    # copy all parames file/binaries
    def copyParams(self, target_dir):
        if (DEBUG): logD("copyParams %s" % target_dir, TAG)
        self.copyParam(self.boot_bin, target_dir)
        self.copyParam(self.boot_param, target_dir)
        self.copyParam(self.cert_param, target_dir)
        self.copyParam(self.cert_bin, target_dir)
        self.copyParam(self.memory_map, target_dir)
        self.copyParam(self.help, target_dir)

    # Parse to prepare parameter, return [error code, error messag]
    # - target_dir: dir to store param files/binaries
    # - filemap: is dictionary, used in case that filename is different from one in memory map
    #            key is target (i.e. bl2, ...), value is fname without extension
    def prepareParam(self, target_dir, filemap=None):
        log("prepareParam", TAG)
        if (DEBUG): logD("target_dir %s" % target_dir, TAG)
        if (DEBUG): logD("filemap %s" % str(filemap), TAG)

        # extract key and value of file map
        filemaptarget = None
        filemapfname = None
        if filemap is not None and len(filemap) > 0:
            log("prepare param, update file mapping", TAG)
            filemaptarget = list(filemap.keys())
            filemapfname = list(filemap.values())
        else:
            filemap = None # set to none, in case filemap is empty dict.
        
        if (DEBUG): logD(self.toString(), TAG)
        if not os.path.exists(PARAM_DIR_PATH):
            logE("not found param dir %s" % PARAM_DIR_PATH, TAG, True)
            return [common.ERR_NOT_FOUND, "Not found param dir"]
        
        # parse boot param and cert header param
        if self.binary_type == common.FIRMWARE:
            log("parse boot_bin", TAG)
            if common.isValidString(self.boot_bin) is not None:
                ret = common.copyFiles(self.boot_bin, target_dir)
                if ret != common.ERR_NONE:
                    logE("prepare boot bin failed %d" % ret, TAG, True)
                    return [ret, "prepare boot bin failed"]

            log("parse boot_param", TAG)
            if common.isValidString(self.boot_param) is not None:
                self.boot_param_dict = self.parseParam(self.boot_param)
            
            log("parse cert_bin", TAG)
            if common.isValidString(self.cert_bin) is not None:
                ret = common.copyFiles(self.cert_bin, target_dir)
                if ret != common.ERR_NONE:
                    logE("prepare cert bin failed %d" % ret, TAG, True)
                    return [ret, "prepare cert bin failed"]

            log("parse cert_param", TAG)
            if common.isValidString(self.cert_param) is not None:
                self.cert_param_dict = self.parseParam(self.cert_param)

        elif self.binary_type == common.FLASHWRITER:
            log("parse boot_bin", TAG)
            if common.isValidString(self.boot_bin) is not None:
                ret = common.copyFiles(self.boot_bin, target_dir)
                if ret != common.ERR_NONE:
                    logE("prepare boot bin failed %d" % ret, TAG, True)
                    return [ret, "prepare boot bin failed"]

            log("parse boot_param", TAG)
            if common.isValidString(self.boot_param) is not None:
                self.boot_param_dict = self.parseParam(self.boot_param)
        else:
            msg = "invalid binary type %s" % self.binary_type
            logE(msg, TAG)
            return [common.ERR_FAILED, msg]

        # parse memory map
        if self.memory_map is not None and len(self.memory_map) > 0:
            log("Parse memory map %s" % self.memory_map, TAG)
            # fmap = os.path.join(PARAM_DIR_PATH, self.memory_map)
            # if not os.path.exists(fmap):
            #     logE("not found memory map %s" % fmap, TAG, True)
            #     return [ret, "not found memory map"]
            
            try:
                content = None
                if (DEBUG): logD("memory_map %s" % self.memory_map, TAG)
                
                with open(self.memory_map, "r") as f:
                    content = f.readlines()
                # Memory map file is in format:
                # <file name no ext> <target, bl2, ..> <memory address> <flash address>
                # i.e. uboot bl32 0x2222 0x3333
                if content is not None:
                    for line in content:
                        if (DEBUG): logD("line %s" % line, TAG)
                        line = line.strip()
                        if len(line) == 0 or line.startswith("#"):
                            continue
                        items = line.split()
                        if items is not None:
                            # require at least 4 elements: fname, target, mem address, flash address
                            # 5th element is optional for vma_address
                            no_item = len(items)
                            if no_item > 3:
                                fname = common.isValidString(items[0])
                                target = common.isValidString(items[1])
                                mem_addr = common.isValidString(items[2])
                                flash_addr = common.isValidString(items[3])
                                vma_addr = common.isValidString(items[4]) if no_item > 4 else None
                                if fname is not None and target is not None and mem_addr is not None and flash_addr is not None:
                                    map = MemoryMap()
                                    name, _ = os.path.splitext(fname)

                                    # replace info with file map if any
                                    # we rely on memory map, and replace fname in memory map with one in file map only.
                                    if filemap is not None:
                                        log("Update memory map with file map", TAG)
                                        # replace fname of target with one in filemap
                                        if target in filemap:
                                            map.fname = filemap[target]
                                        elif name in filemapfname:
                                            idx = filemapfname.index(name)
                                            t = filemaptarget[idx]
                                            if t != target:
                                                continue
                                            else:
                                                map.fname = name
                                        else:
                                            map.fname = name
                                    else:
                                        map.fname = name
                                    
                                    map.target = target
                                    map.mem_addr = mem_addr
                                    map.flash_addr = flash_addr
                                    map.vma_addr = vma_addr
                                    
                                    self.memory_map_dict[map.fname] = map
                                    if (DEBUG): logD("memory_map %s --> %s" % (map.fname, map.toString()), TAG)
                                else:
                                    msg = "Prepare param failed, invalid memory info %s" % line
                                    logE(msg, TAG)
                                    return [common.ERR_INVALID_DATA, msg]
                                # self.memory_map_dict[items[0]] = items
                            else:
                                msg = "Prepare param failed, invalid memory info %s" % line
                                logE(msg, TAG)
                                return [common.ERR_INVALID_DATA, msg]
                        else:
                            logE("not found memory map", TAG, True)
                            return [ret, "not found memory map"]
                    if (DEBUG): logD("memory_map_dict %s" % str(self.memory_map_dict), TAG)
                else:
                    msg = "Prepare param failed, memory map has no info"
                    logE(msg, TAG)
                    return [common.ERR_NO_DATA, msg]
            except:
                traceback.print_exc()
                return [common.ERR_EXCEPTION, "parse memory file failed, exception"]
        else:
            msg = "No memory map info"
            logE(msg, TAG)
            return [common.ERR_NO_DATA, msg]

        if (DEBUG): logD("self.memory_map_dict %s" % str(self.memory_map_dict), TAG)
        return [common.ERR_NONE, "OK"]


####################################################################
# Parameter list
####################################################################
class ParamList:
    paramList = {} # param list, include prebuilt and custom
    paramListUpdateTime = 0 # last update time
    paramList_lock = None # lock for sync access resource

    def __init__(self):
        self.paramList = {}
        self.paramListUpdateTime = 0
        self.paramList_lock = Lock()

    # get param with param id, return "clone" version of param if found, None otherwise
    def getParam(self, id):
        if (DEBUG): logD("getParam %s" % id, TAG)
        param = None
        id = common.isValidString(id)
        if id is not None:
            log("get param for id %s" % id, TAG)
            params = self.getListParam()
            with self.paramList_lock:
                if params is not None and id in params:
                    param = params[id]
                    if (DEBUG): logD("found param %s" % param.toString(), TAG)
                else:
                    logE("not found param id %s" % id, TAG)
        else:
            logE("Invalid id %s" % id, TAG)
        
        if param is not None:
            if (DEBUG): logD("found one, return its clone %s" % param.toString(), TAG)
            return param.clone()
        else:
            logE("getParam failed, Not found param %s" % id, TAG)
            return param

    # convert param list ot json, value is param list want to convert, if not specified, use paramList
    def toJson(self, value=None):
        if (DEBUG): logD("ParamList toJson", TAG)
        params = None
        if value is not None:
            params = value
        else:
            params = self.paramList
        
        if (DEBUG): logD("params %s" % str(params), TAG)
        if params is not None and len(params) > 0:
            if (DEBUG): logD("toJson", TAG)
            try:
                paramObjs = []
                for param in params.values():
                    paramObjs.append(param.toJsonObj())
                
                jdata = {
                    ITEM_PARAM_LIST:paramObjs,
                    }
                jstring = json.dumps(jdata, indent = 4)
                if (DEBUG): logD("jstring %s" % jstring, TAG)
                return jstring
            except:
                traceback.print_exc()
                logE("Convert to json failed", TAG)
                return None
        else:
            logE("to json faile, no params", TAG)
            return None

    # load param file, and return corresponding param list
    def loadParamFile(self, file):
        if (DEBUG): logD("loadParamFile %s" % file, TAG)
        loadparam = {}

        if common.isValidString(file) is not None:
            if os.path.exists(file):
                log("Try to get param list from file", TAG)
                try:
                    with open(file) as jf: # parse json file
                        jdata = json.load(jf)
                        if (DEBUG): logD("jdata %s" % jdata, TAG)
                        # parse each json object
                        jparamlist = common.getJsonObjData(jobj=jdata, name=ITEM_PARAM_LIST, default=[])
                        if jparamlist is not None and len(jparamlist) > 0:
                            for jparam in jparamlist:
                                param = Param(jparam)
                                [ret, msg] = param.validate() # validate if data is valid
                                if ret == common.ERR_NONE:
                                    loadparam[param.id] = param
                                else:
                                    logE("Invalid param info, ret %d. %s" % (ret, msg), TAG)
                                    loadparam = None
                                    break
                            # return loadparam
                        else:
                            logE("Not found any param", TAG)
                except:
                    traceback.print_exc()
                    loadparam = None
            else:
                logE("load param file failed, file not exist", TAG)
                loadparam = {} # file not exist
        else:
            logE("load param file fail, invalid file", TAG)
            loadparam = None
        return loadparam
    
    # Get list of param, return param list which include both list
    def getListParam(self):
        if (DEBUG): logD("getListParam", TAG)

        with self.paramList_lock:
            # check file of prebuilt param list and custome one, if any changes, reload from file, elsee return cached one
            if (DEBUG): logD("list file %s" % PARAM_LIST_PATH, TAG)
            if (DEBUG): logD("paramListUpdateTime %s -> %s" % (self.paramListUpdateTime, datetime.fromtimestamp(self.paramListUpdateTime)), TAG)
            
            # get modified time of both files, get newest one
            mtime_fix = 0
            if os.path.exists(PARAM_LIST_PATH):
                mtime_fix = os.path.getmtime(PARAM_LIST_PATH)
                if (DEBUG): logD("mtime_fix: %s -> %s" % (mtime_fix, datetime.fromtimestamp(mtime_fix)), TAG)

            mtime_cust = 0
            if os.path.exists(CUSTOM_PARAM_LIST_PATH):
                mtime_cust = os.path.getmtime(CUSTOM_PARAM_LIST_PATH)
                if (DEBUG): logD("mtime_cust: %s -> %s" % (mtime_cust, datetime.fromtimestamp(mtime_cust)), TAG)
            
            # get larger one
            mtime = mtime_fix if mtime_fix > mtime_cust else mtime_cust
            if (DEBUG): logD("mtime: %s -> %s" % (mtime, datetime.fromtimestamp(mtime)), TAG)
            
            # check modified time
            # FIXME: in case file is replaced to older one (i.e due to issue), paramlist may not be reloaded
            # Need to make it updated to make modified time of file is changed
            reload = False
            if (self.paramListUpdateTime == 0 or mtime == 0 or mtime != self.paramListUpdateTime) or (self.paramList is None or len(self.paramList) == 0):
                reload = True

            # reload param list from file if need
            if reload:
                log("Reload param list", TAG)
                fix_params = self.loadParamFile(PARAM_LIST_PATH)
                custom_params = self.loadParamFile(CUSTOM_PARAM_LIST_PATH)

                if self.paramList is not None:
                    self.paramList.clear()
                else: 
                    self.paramList = {}
                
                # merge 2 lists into one
                if fix_params is not None:
                    self.paramList.update(fix_params)
                
                if custom_params is not None:
                    self.paramList.update(custom_params)
                
                self.paramListUpdateTime = mtime
            else:
                log("Use cache value", TAG)

        if (DEBUG): logD("params %s" % str(self.paramList.keys()), TAG)
        return self.paramList
    
    # add new param to custome param files, return [code, message]
    # param: param to be add. MUST BE CLONED ONE
    # username: who added this param?
    def addNewParam(self, param, username):
        if (DEBUG): logD("addNewParam %s, %s" % (param.toString(), username), TAG)
        ret = common.ERR_NONE
        msg = ""
        if param is not None:
            # check param name
            # make param name become param id by hashing it
            # why hash but not keep it? it's due to name may contain special char
            name = common.isValidString(param.name)
            if name is not None:
                name = name.lower()
            else:
                logE("add new param failed, invalid name", TAG)
                return [common.ERR_INVALID_ARGS, "invalid name"]
            
            # get custome param from file
            custom_params = self.loadParamFile(CUSTOM_PARAM_LIST_PATH)
            if custom_params is None:
                # try to backup old one if loading failed, and we generate new one
                if os.path.exists(CUSTOM_PARAM_LIST_PATH):
                    log("Backup custom param file", TAG)
                    bkfile = "%s_%s" % (CUSTOM_PARAM_LIST_PATH, common.current_time(common.TIME_FORMAT_TO_FILENAME))
                    shutil.copy(CUSTOM_PARAM_LIST_PATH, bkfile)
                custom_params = {}
            
            with self.paramList_lock:
                try:
                    from server.hash import hashValString
                    from server.hash import ALGO_SHA1
                    # hash name to make id
                    id = hashValString(name, ALGO_SHA1).hex()
                    log("new param id %s" % id, TAG)
                    if id not in custom_params:
                        param.id = id
                        paramdir = os.path.join(PARAM_DIR_PATH, id)
                        # make dir to store data of new param
                        if os.path.exists(paramdir):
                            paramdir = os.path.join(PARAM_DIR_PATH, "%s_%d" % (id, common.current_milli_time()))
                        if not os.path.exists(paramdir):
                            if not common.mkdir(paramdir):
                                ret = common.ERR_FAILED
                                msg = "Failed to make dir %s" % id
                        else:
                            ret = common.ERR_EXISTED
                            msg = "failed to generate folder, as it's existing... please retry"

                        # boot binary
                        if ret == common.ERR_NONE and common.isValidString(param.boot_bin) is not None and os.path.exists(param.boot_bin):
                            log("Copy boot_bin", TAG)
                            if (DEBUG): logD("%s " % param.boot_bin, TAG)
                            
                            dest_dir = os.path.join(paramdir, ITEM_BOOT_BIN)
                            if (DEBUG): logD("dest_dir %s" % dest_dir, TAG)
                            ret = common.copyFiles(param.boot_bin, dest_dir, True, extractZip=False)

                            if ret == common.ERR_NONE:
                                param.boot_bin = os.path.relpath(dest_dir, PARAM_DIR_PATH)
                            else:
                                msg = "copy boot_bin failed"
                        else:
                            log("Skip boot_bin")

                        # boot param
                        if ret == common.ERR_NONE and common.isValidString(param.boot_param) is not None and os.path.exists(param.boot_param):
                            log("Copy boot_param", TAG)
                            if (DEBUG): logD("%s " % param.boot_param, TAG)
                            dest_file = os.path.join(paramdir, ITEM_BOOT_PARAM)
                            if (DEBUG): logD("dest_file %s" % dest_file, TAG)
                            shutil.copy(param.boot_param, dest_file)
                            param.boot_param = os.path.relpath(dest_file, PARAM_DIR_PATH)
                        else:
                            log("Skip boot_param")
                        
                        # cert bin
                        if ret == common.ERR_NONE and common.isValidString(param.cert_bin) is not None and os.path.exists(param.cert_bin):
                            log("Copy cert_bin", TAG)
                            if (DEBUG): logD("%s " % param.cert_bin, TAG)
                            dest_dir = os.path.join(paramdir, ITEM_CERT_BIN)
                            ret = common.copyFiles(param.cert_bin, dest_dir, True, extractZip=False)
                            if (DEBUG): logD("dest_dir %s" % dest_dir, TAG)
                            if ret == common.ERR_NONE:
                                param.cert_bin = os.path.relpath(dest_dir, PARAM_DIR_PATH)
                            else:
                                msg = "copy cert_bin failed"
                        else:
                            log("Skip cert_bin")
                        
                        # cert param
                        if ret == common.ERR_NONE and common.isValidString(param.cert_param) is not None and os.path.exists(param.cert_param):
                            log("Copy cert_param", TAG)
                            if (DEBUG): logD("%s " % param.cert_param, TAG)
                            dest_file = os.path.join(paramdir, ITEM_CERT_PARAM)
                            if (DEBUG): logD("dest_file %s" % dest_file, TAG)
                            shutil.copy(param.cert_param, dest_file)
                            param.cert_param = os.path.relpath(dest_file, PARAM_DIR_PATH)
                        else:
                            log("Skip cert_param")
                        
                        # memory map file
                        if ret == common.ERR_NONE and common.isValidString(param.memory_map) is not None and os.path.exists(param.memory_map):
                            log("Copy memory_map", TAG)
                            if (DEBUG): logD("%s " % param.memory_map, TAG)
                            dest_file = os.path.join(paramdir, ITEM_MEMORY_MAP)
                            if (DEBUG): logD("dest_file %s" % dest_file, TAG)
                            shutil.copy(param.memory_map, dest_file)
                            param.memory_map = os.path.relpath(dest_file, PARAM_DIR_PATH)
                        else:
                            log("Skip memory_map")

                        # help file
                        if ret == common.ERR_NONE and common.isValidString(param.help) is not None and os.path.exists(param.help):
                            log("Copy help", TAG)
                            if (DEBUG): logD("%s " % param.help, TAG)
                            dest_file = os.path.join(paramdir, ITEM_HELP)
                            if (DEBUG): logD("dest_file %s" % dest_file, TAG)
                            shutil.copy(param.help, dest_file)
                            param.help = os.path.relpath(dest_file, PARAM_DIR_PATH)
                        else:
                            log("Skip help")

                        # update last update time and user who add new param
                        if ret == common.ERR_NONE:
                            param.last_update = common.current_time(common.TIME_FORMAT_TO_DISPLAY_ZONE)
                            param.source = username
                            custom_params[id] = param
                            jstring = self.toJson(custom_params)
                            # restore to custome param list file
                            if jstring is not None:
                                if common.write_string_to_file(CUSTOM_PARAM_LIST_PATH, jstring, force=True):
                                    ret = common.ERR_NONE
                                    msg = "OK"
                                else:
                                    ret = common.ERR_FAILED
                                    msg = "Save to custome param list failed"
                            else:
                                ret = common.ERR_FAILED
                                msg = "Nothing to save"
                    else:
                        ret = common.ERR_EXISTED
                        msg = "name already existed"
                except:
                    traceback.print_exc()
                    ret = common.ERR_EXCEPTION
                    msg = "Exeption occurs"
                    
        else:
            ret = common.ERR_FAILED
            msg = "Invalid param"

        # well done
        if (DEBUG): logD("ret %d msg %s" % (ret, msg), TAG)
        return [ret, msg]


s_paramList = ParamList()

def getListParam():
    if (DEBUG): logD("getListParam", TAG)
    return s_paramList.getListParam()

def getParam(name):
    if (DEBUG): logD("getParam", TAG)
    return s_paramList.getParam(name)

def addNewParam(param, username):
    if (DEBUG): logD("addNewParam", TAG)
    return s_paramList.addNewParam(param, username)