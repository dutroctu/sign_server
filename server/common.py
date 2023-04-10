#!/usr/bin/env python
#
#  ENTRY FOR SERVER
#

import sys
import os
import time
import hashlib
import shutil
import traceback
import zipfile
import uuid
import random
from datetime import datetime
from server.applog import logE
from server.applog import logD
from server.applog import log
import socket

import random
import string
import ast

TAG="common"

# default key id
DEFAULT_KEY_ID = "default"
NONE_KEY_ID = "none"
DEFAULT="default"
ANY_INFO="any"
CUSTOM="custom"
# invalid key id
INVALID_KEY_ID = "invalid"

BUF_SIZE = 65536


FIRMWARE="firmware"
FLASHWRITER="flashwriter"

DEFAULT_PASSWORD_LENGTH=8

# HTTP response code
ERR_HTTP_RESPONSE_BAD_REQ = 400
ERR_HTTP_RESPONSE_OK = 200

# ERROR code
ERR_NONE = 0
ERR_FAILED = -1
ERR_EXPIRED = -2
ERR_NO_UUID = -3
ERR_INVALID_DATA = -4
ERR_INVALID_ARGS = -5
ERR_EXISTED = -6
ERR_NOT_FOUND = -7
ERR_NO_DATA = -8
ERR_NOT_EXISTED = -9
ERR_NOT_MATCH = -10
ERR_INACTIVE = -11
ERR_INVALID = -12
ERR_NOT_READY = -14
ERR_EXCEPTION = -15
ERR_NOT_SUPPORT = -16
ERR_PROHIBIT = -17
ERR_REQUIRE_AUTHEN = -18
ERR_BUSY = -19
ERR_CORRUPT = -20
ERR_LOCKED = -21
ERR_TIMEOUT = -22


# match between code to message
ERR_MSG = {
    ERR_NONE: "OK",
    ERR_FAILED: "ERR_FAILED",
    ERR_EXPIRED: "ERR_EXPIRED",
    ERR_NO_UUID: "ERR_NO_UUID",
    ERR_INVALID_DATA: "ERR_INVALID_DATA",
    ERR_INVALID_ARGS: "ERR_INVALID_ARGS",
    ERR_EXISTED: "ERR_EXISTED",
    ERR_NOT_FOUND: "ERR_NOT_FOUND",
    ERR_NO_DATA: "ERR_NO_DATA",
    ERR_NOT_EXISTED: "ERR_NOT_EXISTED",
    ERR_NOT_MATCH: "ERR_NOT_MATCH",
    ERR_INACTIVE: "ERR_INACTIVE",
    ERR_INVALID: "ERR_INVALID",
    ERR_NOT_READY: "ERR_NOT_READY",
    ERR_EXCEPTION: "ERR_EXCEPTION",
    ERR_NOT_SUPPORT: "ERR_NOT_SUPPORT",
    ERR_PROHIBIT: "ERR_PROHIBIT",
    ERR_REQUIRE_AUTHEN: "ERR_REQUIRE_AUTHEN",
    ERR_BUSY: "ERR_BUSY",
}

# PARAM definition
PARAM_API = "api"

PARAM_ACCESS_TOKEN = "access_token"
PARAM_MODEL = "model"
PARAM_KEY_TYPE = "key_type"
PARAM_ZIP_OUTPUT = "zip_output"
PARAM_NAME = "name"
PARAM_TITLE = "title"
PARAM_TAG = "tag"
PARAM_ALG = "alg"
PARAM_ALG_ID = "algo_id"
PARAM_PASSWORD = "password"
PARM_HINT = "hint"
PARAM_KEY_DATA = "keydata"
PARAM_DATA_TYPE = "data_type"
PARAM_PROJECT = "project"
PARAM_USERNAME = "username"
PARAM_REMEMBER = "remember"
PARAM_NEXT = "next"
PARAM_KEY_ID = "key_id"
PARAM_KEY_NAME = "key_name"
PARAM_SIGN_ID = "sign_id"
PARAM_TYPE = "type"
PARAM_IS_SEPARATE = "is_separate"
PARAM_COMMAND = "command"
PARAM_TOOL = "tool"
PARAM_KEYTOOL = "keytool"
PARAM_SCHEME = "scheme"
PARAM_DEFAULT = "default"
PARAM_OTA = "ota"
PARAM_IMAGE = "image"
PARAM_PARITION = "partition"
PARAM_VERSION = "version"

SREC_EXT = [".srec", ".mot"]

COMMAND_TIMEOUT_MIN=30
COMMAND_TIMEOUT_SECOND=(COMMAND_TIMEOUT_MIN*60)


ACTION_HELP="help"
ACTION_DOWNLOAD="download"

def isDebug():
    from server.app import DEBUG
    return DEBUG

# check if zip param is set
def isZip(zip_param):
    return True if zip_param and (zip_param == 'on' or zip_param == True or zip_param == 'True') else False


def isRequestSelected(param):
    return True if param and (param == 'on' or param == True or param == 'True') else False

# convert error message from code to string
def get_err_msg(code):
    return ERR_MSG[code] if code in ERR_MSG else "unknown"

# get current time in ms
def current_milli_time():
    return round(time.time() * 1000)

# get current time
# format: "%m/%d/%Y, %H:%M:%S.%f"
TIME_FORMAT_TO_DISPLAY="%Y/%m/%d, %H:%M:%S.%f"
TIME_FORMAT_TO_DISPLAY_SHORT="%Y/%m/%d[%H:%M:%S]"
TIME_FORMAT_TO_FILENAME="%Y%m%d_%H%M%S%f"
# 2021/05/24 18:00:00+0700
TIME_FORMAT_TO_DISPLAY_ZONE="%Y/%m/%d, %H:%M:%S%z"
def current_time(format=None): 
    now = datetime.utcnow()
    if (format is not None):
        return now.strftime(format)
    else:
        return now
# write bytes buffer to file.
# caller MUST CONVERT string data to bytes buffer before calling this funciton, i.e. bytes(data, 'utf-8')
def write_to_file(path, data, force=True):
    if (isDebug()): logD("write_to_file to %s" % (path), TAG)
    if ((path is not None) and len(path) > 0):
        if  (not os.path.exists(path)) or force == True:
            try:
                with open(path, 'wb+') as f:
                    f.write(data)
                if (isDebug()): logD("Write done", TAG)
                return True
            except:
                traceback.print_exc()
                logE("Write failed", TAG)
                return False
    if (isDebug()): logD("Write failed", TAG)
    return False

def write_string_to_file(path, data, force=True):
    if (isDebug()): logD("write_string_to_file %s" % (data), TAG)
    return write_to_file(path, bytes(data, 'utf-8'), force)

def appendStringToFile(data, path):
    if (isDebug()): logD("appendStringToFile %s to %s" % (data, path), TAG)
    if ((path is not None) and len(path) > 0 and data is not None and len(data) > 0):
        try:
            with open(path, 'a+') as f:
                f.write(data)
                f.write('\n')
            if (isDebug()): logD("Write done")
            return True
        except:
            traceback.print_exc()
            if (isDebug()): logD("Write failed")
            return False
    if (isDebug()): logD("Write failed")
    return False

def read_string_from_file(path):
    data = None
    try:
        with open(path, 'r') as f:
            data = f.read()
    except:
        traceback.print_exc()
    finally:
        return data

def read_from_file_to_base64(path):
    data = None
    try:
        rawdata = None
        with open(path, 'rb') as f:
            rawdata = f.read()
        data = base64.b64encode(rawdata).decode('utf-8')
        if (isDebug()): logD("conver %s to %s" % (path, data))
    except:
        traceback.print_exc()
    finally:
        return data

def rm_file_in_dir(dir):
    if (isDebug()): logD("rm_file_in_dir %s" %dir)
    if (dir is not None) and len(dir) > 0 and os.path.exists(dir):
        for f in os.listdir(dir):
            path = os.path.join(dir, f)
            if os.path.isfile(path):
                if (isDebug()): logD("rm %s" % path)
                os.remove(path)
            else:
                if (isDebug()): logD("skip dir %s" % path)


# check and remove dirs
def rmdirs(dir, ignore_errors=True):
    if (isDebug()): logD("rm %s" %dir)
    if (dir is not None) and len(dir) > 0 and os.path.exists(dir):
        shutil.rmtree(dir, ignore_errors)

# check to make dirs, return True on success
def mkdir(dir, force=True, ignore_errors=True):
    if (isDebug()): logD("mkdir %s" % dir)
    if (dir is not None) and len(dir) > 0:
        if os.path.exists(dir):
            if force:
                shutil.rmtree(dir, ignore_errors=True)
            else:
                logE("Dir %s exist, set force to delete if need" % dir)
                return False

        os.makedirs(dir, mode=0o775)
        return True
    else: # invalid dir
        logE("Invalid dir")
        return False

SPECIAL_CHAR="\/:*?<> |\"\'\\"

# remove all special char in file name
def normalize_fname(fname):
    if (isDebug()): logD("normalize_fname, SPECIAL_CHAR %s" % SPECIAL_CHAR, TAG)
    return "".join(i for i in fname if i not in SPECIAL_CHAR)

# valide if name contain any special charater
def validate_usrname(fname):
    if (isDebug()): logD("validate_usrname, SPECIAL_CHAR %s" % SPECIAL_CHAR, TAG)
    if fname is not None and len(fname) > 0:
        for i in fname:
            if i in SPECIAL_CHAR:
                if (isDebug()): logD("Include special char %s" % (i), TAG)
                return False # contain invalid charactor
        
        if (isDebug()): logD("Not include special char", TAG)
        return True
    else: # invalid input
        logE("validate failed, invalid input", TAG)
        return False

# add backsplash for special char
def add_backsplash_for_special_char(fname):
    if (isDebug()): logD("add_backsplash_for_special_char, SPECIAL_CHAR %s" % SPECIAL_CHAR, TAG)
    if (isDebug()): logD("add_backsplash_for_special_char, fname %s" % fname, TAG)
    finalstr = ""
    for i in fname:
        if i not in SPECIAL_CHAR:
            finalstr += i
        else:
            finalstr += "\\%c" % i
    if (isDebug()): logD("--> finalstr: %s" % finalstr, TAG)
    return finalstr

# search files in folder
def search_files(dirName):
 
  output = []
   
  for root, dirs, files in os.walk(dirName):
    for filename in files:
        file = os.path.join(root, filename)
        output.append(file)
         
  return output # return full path of found files
 

# zip folder to a file
# return True on success, else return False
def zipfolder(folder, out_file, override=True):
    if (isDebug()): logD("zip folder %s to file %s, override %d" % (folder, out_file, override))

    # check if folder exist
    if (not os.path.exists(folder)):
        logE("%s is not exist" % folder)
        return False

    # if output file already exist, check if we need to override it or not
    if (os.path.exists(out_file)) and not override:
        logE("%s is exist and not override" % out_file)
        return False

    # search all filese in input folder
    filePaths = search_files(folder)

    # let's start zipping
    from server import app as app
    if (len(filePaths) > 0):
        if app.DEBUG: # print log for debug
            logE("Files to be zipped")
            for file in filePaths:
                if (isDebug()): logD(file)
        try:
            zip_file = zipfile.ZipFile(out_file, 'w')
            with zip_file:
                for file in filePaths: #scan each file and add to zip file
                    if (file != out_file):
                        if (isDebug()): logD("add %s"  % file)
                        # add to zip file
                        zip_file.write(file, os.path.relpath(file, folder)) # relate path only
                    else:
                        if (isDebug()): logD("Is out file skip %s"  % file)
            return True
        except :
            traceback.print_exc()
            if (isDebug()): logD("zip %s failed"  % folder)
            return False
    else:
        logE("%s is empty" % folder)
        return False
    return False


# unzip file to folder
# return True on success, else return False
def unzip_file(zip_file, out_folder, override=True):
    if (isDebug()): logD("zip folder %s to file %s, override %d" % (zip_file, out_folder, override))

    # check if folder exist
    if (not os.path.exists(zip_file)):
        logE("%s is not exist" % zip_file)
        return False

    # create output folder if not exist
    mkdir(out_folder, False)

    # let's start unzip
    try:
        log("Unzip %s to %s" % (zip_file, out_folder))
        with zipfile.ZipFile(zip_file, 'r') as zip_ref:
            zip_ref.extractall(out_folder)
    except:
        traceback.print_exc()
        logE("Unzip %s failed" % zip_file)
        return False
    return True

def isZipFile(path):
    if path is not None and len(path) > 0 and path.endswith(".zip"):
        return True
    # TODO: check content
    return False

# generate uuid
def gen_uuid():
    _uuid = str(uuid.uuid4())
    return _uuid

# get random number (integer)
def get_randint():
    random.seed(current_milli_time())
    # TODO: check python version
    # return random.randint(0, sys.maxint) # python2
    return random.randint(0, sys.maxsize)

# get random string
def get_randstring(length = 0):
    random.seed(current_milli_time())
    # TODO: check python version, length
    # return random.randint(0, sys.maxint) # python2
    rand = random.randint(0, sys.maxsize)
    import server.hash
    return server.hash.sha1(bytes("%s" % rand, 'utf-8'))

# check if url is save
from urllib.parse import urlparse, urljoin
def is_safe_url(target, request):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc

# extract value of param in request
def extract_form_request(req, name, is_int=False, default_data="", getlist=False):
    # TODO: other type?
    # TODO: check input
    if (isDebug()): logD("extract_form_request for: %s" % (req.form), TAG)
    if getlist:
        res = req.form.getlist(name) if name in req.form else None
    else:        
        if not is_int: #is integer value
            res = req.form.get(name) if name in req.form else default_data
        else:
            res = req.form.get(name, type=int) if name in req.form else default_data
    
    if (isDebug()): logD("%s ==> %s" % (name, str(res)), TAG)
    return res

def isCheckParam(req, param):
    check = req.form.get(param) if param in req.form else None
    return isZip(check) if check is not None else False

import base64
def encodeBase64(data):
    return base64.urlsafe_b64encode(data).decode() if data is not None else None
    
def decodeBase64(data):
    return base64.urlsafe_b64decode(data)


#get my ip
def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('8.8.8.8', 80))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP


def getRandomString(N=DEFAULT_PASSWORD_LENGTH):
    return ''.join(random.choices(string.ascii_lowercase + string.ascii_uppercase + string.digits, k=N))

# Return None on empty or invalid
def string2List(str):
    try:
        lst = ast.literal_eval(str) if str is not None and len(str) > 0 else None
        return lst if lst is not None and len(lst) > 0 else None
    except:
        traceback.print_exc()
        logE("string2List %s failed" % str)
        return None

def getJsonObjData(jobj, name, default=None):
    val = jobj[name] if name in jobj else default
    return val


def extractKeyInfo(request, project=None, model=None, signtool=None, param_key_id = None, param_key_name = None, keytool = None):
    if (isDebug()): logD("getKeyInfo param_key_id %s param_key_name %s keytool %s" % (param_key_id, param_key_id, keytool), TAG)
    from server.key.key_mng import keyMgr
    key_id = extract_form_request(request, param_key_id) if param_key_id is not None else None
    key_info = None
    if key_id is None or len(key_id) == 0:
        if (isDebug()): logD("no keyid, get from keyname", TAG)
        key_name = extract_form_request(request, param_key_name) if param_key_name is not None else None
        if key_name is not None and len(key_name) > 0: #if key name, need to match with project and model
            if key_name != DEFAULT_KEY_ID and key_name != NONE_KEY_ID:
                key_info = keyMgr().get_key_by_name(
                                    key_name, 
                                    project=project, 
                                    model=model,
                                    tool=signtool,
                                    keytool=keytool
                                    )
                if (key_info is not None):
                    key_id = key_info.id
                else:
                    # key_id = None
                    key_id = INVALID_KEY_ID
            else: # key name is default, let's search default key
                key_id = key_name
            
        else: # no key id nor key name
            key_id = None
        
    elif key_id != DEFAULT_KEY_ID and key_id != NONE_KEY_ID: # not default key, try to search
        
        if (isDebug()): logD("get key from keyid %s" % key_id, TAG)
        key_info = keyMgr().get_key(key_id)
        if key_info is None:
            logE("not found keyid %s" % key_id)
            # key_id = None
            key_id = INVALID_KEY_ID
        else:
            key_id = key_info.id
    # else: search default key later

    if key_id == DEFAULT_KEY_ID:
        if (isDebug()): logD("get default", TAG)
        key_info = keyMgr().get_default_key(project, model, signtool, keytool)
        if key_info is None:
            log("Not found default key, use default in tool if exists")
        else:
            key_id = key_info.id
    elif key_id == NONE_KEY_ID:
        key_id = None
        key_info = None

    return [key_id, key_info]

def copyFiles(source, dest, create_dest_dir=True, extractZip=True):
    if (isDebug()): logD("copyFiles %s to %s" % (source, dest), TAG)

    if not os.path.exists(dest):
        if create_dest_dir:
            mkdir(dest)
        else:
            logE("not found dest %s" % dest, TAG)
            return ERR_NOT_FOUND

    if not os.path.exists(source):
        logE("not found source %s" % source, TAG)
        return ERR_NOT_FOUND
    
    if os.path.isfile(source):
        if isZipFile(source) and extractZip:
            if (isDebug()): logD("Unzip file", TAG)
            if not unzip_file(source, dest):
                logE("unzip_file %s to %s failed" % (source, dest), TAG, True)
                return ERR_FAILED
        else:
            if (isDebug()): logD("copy file", TAG)
            shutil.copy(source, dest)
    else:
        if (isDebug()): logD("copy files in dir %s to %s" % (source, dest), TAG)
        for fname in os.listdir(source):
            fpath = os.path.join(source, fname)
            if (isDebug()): logD("fpath %s" % fpath, TAG)
            shutil.copy(fpath, dest)

    return ERR_NONE

def runCommand(cmd, timeout=COMMAND_TIMEOUT_SECOND):
    res = -1
    if (isDebug()): logD("runCommand %s, timeout %d" % (cmd, timeout), TAG)
    try:
        import subprocess
        child = subprocess.run(cmd, shell=True, timeout=timeout if timeout > 0 else None)
        res = child.returncode
    except:
        traceback.print_exc()
        return ERR_EXCEPTION

    # check result
    if (isDebug()): logD("command %s" % str(res))
    return ERR_NONE if res == 0 else ERR_FAILED

def runCommandWithOutput(command, readLine = True):
    if (isDebug()): logD("runCommandWithOutput %s readLine %d" % (command, readLine), TAG)
    try:
        stream = os.popen(command)
        if readLine:
            ostream = stream.readlines()
        else:
            ostream = stream.read()
        return ostream
    except:
        traceback.print_exc()
        return None

def isValidString(val):
    if val is not None:
        vals = val.strip()
        if len(vals) > 0:
            return vals
        else:
            return None
    return None

# def string2Bytes(str):
#     try:
#         import binascii
#         if str.startswith("0x"):
#             str = str[2:]
#             strlen = len(str) * 4
        
#     except:
#         traceback.print_exc()
#         logE("string2List %s failed" % str)
#         return None