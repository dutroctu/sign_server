#!/usr/bin/env python
#
#  ENTRY FOR SERVER
#

from flask import Flask, Blueprint, redirect, url_for, g
from flask_restful import Api, Resource, reqparse
from flask import send_file
from flask import render_template
import sys
import os
# import server.applog
from server.applog import log
from server.applog import logE
from server.applog import logD
from server.applog import init_log
import socket
from flask import request, send_from_directory, jsonify
import time
from server import common as common
from server import ver as ver
from server import dbg as dbg
# from .common from server import common as common

from flask_login import login_required, current_user
import atexit
import traceback
import json

#Root application dir
if __name__ == "__main__":
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
else:
    from __main__ import ROOT_DIR


from server.app_config import AppConfig

VERSION_MAJOR=ver.VERSION_MAJOR
VERSION_MINOR=ver.VERSION_MINOR
VERSION_PATCH=ver.VERSION_PATCH
GIT_COMMIT=ver.GIT_COMMIT

VERSION_CODE=VERSION_MAJOR*10000 + VERSION_MINOR*100 + VERSION_PATCH
VERSION_NAME="%s.%s.%s.%s" % (VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH,GIT_COMMIT)
VERSION_STRING="%s (%d)" % (VERSION_NAME, VERSION_CODE)

DEBUG = dbg.DEBUG
DEBUG_DB = dbg.DEBUG_DB
KEEP_OUTPUT_FILE = dbg.DEBUG_DB
MONITOR_WAIT_TIMEOUT = dbg.MONITOR_WAIT_TIMEOUT

# DEBUG = True
# DEBUG_DB = True
# KEEP_OUTPUT_FILE = True
KEEP_OUTPUT_FILE = DEBUG

TAG = "app"


STATIC_FOLDER=None
TEMPLATE_FOLDER=None
BASE_DIR = ROOT_DIR
if hasattr(sys, '_MEIPASS'): 
    BASE_DIR =  sys._MEIPASS
STATIC_FOLDER = os.path.join(BASE_DIR, 'static')
TEMPLATE_FOLDER = os.path.join(BASE_DIR, 'templates')


#global object 
app = Flask(__name__, template_folder=TEMPLATE_FOLDER, static_folder=STATIC_FOLDER)
app.config["DEBUG"] = DEBUG
api = Api(app)


main = Blueprint('main', __name__)


INPUT_DIRECTORY_NAME = ".input"
OUTPUT_DIRECTORY_NAME = ".output"
DOWNLOAD_DIRECTORY_NAME = ".download"
ROOT_DATA_DIRECTORY_NAME = ".data"
ROOT_TEMP_DIRECTORY_NAME = ".tmp"

ROOT_TOOL_DIRECTORY_NAME = "tool"

appconfig = AppConfig()

def getRootToolDir():
    return os.path.join(ROOT_DIR, ROOT_TOOL_DIRECTORY_NAME)


def getAppConfigFile():
    global DEFAULT_APP_CONFIG_FILE
    return DEFAULT_APP_CONFIG_FILE

def getRootDataDir():
    return appconfig.getDataPath()

def getRootTempDir():
    return appconfig.getTempPath()

# anhnh57 2022/03/11: make input/output/download/log more configuratble in config.json
def getRootInputDir():
    # return appconfig.getTempPath(INPUT_DIRECTORY_NAME)
    return appconfig.getInputPath()

def getRootOutputDir():
    # return appconfig.getTempPath(OUTPUT_DIRECTORY_NAME)
    return appconfig.getOutputPath()

def getRootDownloadDir():
    # return appconfig.getTempPath(DOWNLOAD_DIRECTORY_NAME)
    return appconfig.getDownloadPath()

def getRootLogDir():
    # return appconfig.getTempPath(DOWNLOAD_DIRECTORY_NAME)
    return appconfig.getLogPath()

def getProjectList():
    return appconfig.getProjectList()

def getModelList():
    return appconfig.getModelList()

def getDocDir():
    return DOCUMENT_DIRECTORY

def getResDir():
    return RESOURCE_DIRECTORY

def is_debug():
    return DEBUG

def is_debug_db():
    return False if not DEBUG else DEBUG_DB

def getAutoDeleteTime():
    return appconfig.get_auto_del_time()

#common response to client
def get_resp(error, message=None, data=None, status_code=0):
    msg = {'code':error}
    if (message is not None):
        msg['message'] = message
    if data is not None:
        msg['data'] = data
    __resp = jsonify(msg)
    __resp.status_code = error if status_code == 0 else status_code
    return __resp

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


def on_app_exit():
    logE("SERVER EXIT!!!")
    from server.storage import exit_storage_management
    exit_storage_management(app)

    if not KEEP_OUTPUT_FILE:
        common.rmdirs(getRootTempDir())
    
    from server.monitor.system_monitor import stop_system_monitor
    stop_system_monitor()


import server.login.login_api_handling
import server.sign.sign_api_handling
import server.fota.fota_api_handling
import server.key.key_api_handling
import server.database.db_api_handling
import server.admin.admin_api_handling
import server.doc.doc_api_handling
import server.resource.res_api_handling



# homepage
# @app.route('/', methods=['GET'])
@main.route('/')
def home():
    # FIXME: I tried url_value_preprocessor and catch all routes to make common processing, but not success
    # if you find better way, please update this :)
    import server.monitor.system_report
    checkResp = server.monitor.system_report.check_system(request)
    if checkResp is not None:
        return checkResp
    from server.login.login import is_login, current_username
    version = VERSION_STRING + (". DEBUG MODE" if DEBUG else "")
    if (DEBUG): logD("version %s" % version, TAG)
    return render_template("index.html"
            , login=is_login(request)
            , username=current_username()
            , version= version
            )

@app.route('/setup', methods=['GET','POST'])
def setup():
    import server.monitor.system_report
    if not server.monitor.system_report.sysReport().isReady():
        if request.method == 'POST':
            dbkey = common.extract_form_request(request, 'database')
            if dbkey is not None:
                dbkey.strip()
            filekey = common.extract_form_request(request, 'storage')
            if filekey is not None:
                filekey.strip()
            if (dbkey is not None and len(dbkey) > 0) and (filekey is not None and len(filekey) > 0):
                ret = setup(filekey, dbkey, True)
                if ret != common.ERR_NONE or not server.monitor.system_report.sysReport().isReady():
                    logE("setup failed, or system not ready", TAG)
                    return get_resp(
                    error=-1, 
                    message="Failed to setup", 
                    status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
                else:
                    log("all well, to to home", TAG)
                    return get_resp(
                        error=0, 
                        message="OK", 
                        status_code=common.ERR_HTTP_RESPONSE_OK)
            else:
                logE("failed, not enough input", TAG)
                return get_resp(
                    error=-1, 
                    message="Invalid input", 
                    status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)

        else:
            from server.database.db_mgr import dbMgr
            from server.storage.storage_mgr import storageMgr
            try:
                dbpass = dbMgr().isPasswordSet()
                filepass = storageMgr().isPasswordSet()
                return render_template("setup.html"
                        , needsetup=not server.monitor.system_report.sysReport().isReady()
                        , needsetupdb = not dbpass
                        , needsetupfile = not filepass
                        , needlogindb = False
                        )
            except:
                traceback.print_exc()
                return render_template("setup.html"
                        , needsetup=not server.monitor.system_report.sysReport().isReady()
                        , needsetupdb = True
                        , needsetupfile = True
                        , needlogindb = True
                        )
    else:
        log("all well, to to home", TAG)
        return redirect(url_for('main.home'))

import getopt

PARAM_SHORT_ARG="hc:d:f:"
PARAM_LONG_ARG=["help", "config=","dbkey=","filekey=","cert=","key="]

def printHelp():
    print ("\nCommand:")
    print("\t%s -h|--help -d|--config <config file path> -d|--dbkey <pwd to encrypt database> -f|--filekey <pwd to encrypt file>" % os.path.basename(sys.argv[0]))
    print ("\n")

def setup(fileKey, dbkey, auto_set_pass = False):
    log("Do setup ... ", TAG)

    log("Setup database", TAG, toFile=False)
    if (dbkey is not None and len(dbkey) > 0):
        from server.database.db_mgr import setup_database
        ret = setup_database(app, dbkey, auto_set_pass)
        if ret != common.ERR_NONE:
            logE("Setup db management failed %d" % ret, TAG)
            return ret
    else:
        logE("setup db failed, no key", TAG)
        return common.ERR_FAILED

    log("Setup storage", TAG, toFile=False)
    if (fileKey is not None and len(fileKey) > 0):
        from server.storage import setup_storage_management
        ret = setup_storage_management(app, fileKey, auto_set_pass)
        if ret != common.ERR_NONE:
            logE("Setup storage management failed %d" % ret, TAG)
            return ret
    else:
        logE("setup storage failed, no key", TAG)
        return common.ERR_FAILED


    log("Setup UserMgr", TAG, toFile=False)
    import server.monitor.system_report
    if server.monitor.system_report.sysReport().isReady():
        from server.login.user_mng import setup_user_management
        ret = setup_user_management()
        if ret != common.ERR_NONE:
            logE("Setup user management failed %d" % ret, TAG)
            return ret
    else:
        logE("setup failed, not ready", TAG)
        return common.ERR_NOT_READY

    log("Setup app done", TAG)
    return common.ERR_NONE

def create_app(dbusr=None, dbpass=None, db=None, file=None, workingdir=ROOT_DIR, appconfigPath=None, dbName=None, runlog=None):
    print ("Signing server, version: %s\n" % VERSION_STRING)
    if (DEBUG): log("!!!!!!!!!!!APP IS STARTED IN DEBUG MODE!!!!!!!!!!!", TAG)
    else:
        log("APP IS STARTED IN RELEASE MODE", TAG)

    log("Create app")

    dbkey=db
    filekey=file
    global ROOT_DIR
    ROOT_DIR=workingdir if workingdir is not None else ROOT_DIR
    # log("ROOT_DIR %s" % ROOT_DIR)
    
    global DEFAULT_APP_CONFIG_FILE
    DEFAULT_APP_CONFIG_FILE = os.path.join(ROOT_DIR, "config.json")

    global RESOURCE_DIRECTORY
    RESOURCE_DIRECTORY = os.path.join(ROOT_DIR, "resource")

    global DOCUMENT_DIRECTORY
    DOCUMENT_DIRECTORY = os.path.join(ROOT_DIR, "doc")

    configPath=appconfigPath if appconfigPath is not None else DEFAULT_APP_CONFIG_FILE

    if (os.path.exists(configPath)):
        appconfig.loadFile(configPath)



    # PROJECT_LIST = appconfig.getProjectList()

    # MODEL_LIST = appconfig.getModelList()

    # ROOT_DATA_DIRECTORY = appconfig.getDataPath()
    # ROOT_TEMP_DIRECTORY = appconfig.getTempPath()

    # INPUT_DIRECTORY = appconfig.getTempPath(INPUT_DIRECTORY_NAME)
    # OUTPUT_DIRECTORY = appconfig.getTempPath(OUTPUT_DIRECTORY_NAME)
    # DOWNLOAD_DIRECTORY = appconfig.getTempPath(DOWNLOAD_DIRECTORY_NAME)

    if (DEBUG): logD("ROOT_DATA_DIRECTORY %s" % getRootDataDir(), TAG)
    if (DEBUG): logD("ROOT_TEMP_DIRECTORY %s" % getRootTempDir(), TAG)
    if (DEBUG): logD("INPUT_DIRECTORY %s" % getRootInputDir(), TAG)
    if (DEBUG): logD("OUTPUT_DIRECTORY %s" % getRootOutputDir(), TAG)
    if (DEBUG): logD("DOWNLOAD_DIRECTORY %s" % getRootDownloadDir(), TAG)
    if (DEBUG): logD("MODEL_LIST %s" % getModelList(), TAG)
    if (DEBUG): logD("PROJECT_LIST %s" % getProjectList(), TAG)
    if (DEBUG): logD("TEMPLATE_FOLDER %s" % TEMPLATE_FOLDER, TAG)
    if (DEBUG): logD("STATIC_FOLDER %s" % STATIC_FOLDER, TAG)


    # clean up generated working folders
    #TODO: check to clean up input/output folder
    if not KEEP_OUTPUT_FILE:
        common.rmdirs(getRootTempDir())

    # check to generate workign folder
    if not os.path.exists(getRootInputDir()):
        os.makedirs(getRootInputDir())

    if not os.path.exists(getRootOutputDir()):
        os.makedirs(getRootOutputDir())

    if not os.path.exists(getRootDownloadDir()):
        os.makedirs(getRootDownloadDir())

    if not os.path.exists(getRootDataDir()):
        os.makedirs(getRootDataDir())

    if not os.path.exists(getRootLogDir()):
        os.makedirs(getRootLogDir())

    # init log dir
    init_log(getRootLogDir(), runlog)
    
    atexit.register(on_app_exit)



    local_ip = appconfig.get_ip()
    port = appconfig.get_port()
    app.config['SECRET_KEY'] = common.get_randstring()

    
    # blueprint for auth routes in our app
    from server.login.login import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    # blueprint for non-auth parts of app
    app.register_blueprint(main)


    from server.database.db_mgr import init_database
    from server.database.db_mgr import dbMgr
    dbport = appconfig.get_dbport()
    log("Initializa DB %s:%d, name: %s" % (local_ip, dbport, dbName), TAG, toFile=False)
    ret = init_database(app, local_ip, dbport, dbusr, dbpass, dbName)
    if ret != common.ERR_NONE:
        logE("Init database failed %d" % ret, TAG)
        sys.exit(1)

    from server.monitor.system_report import init_system_report
    log("Initializa system report", TAG, toFile=False)
    ret = init_system_report(app)
    if ret != common.ERR_NONE:
        logE("Init system report failed %d" % ret, TAG)
        sys.exit(1)

    from server.monitor.system_monitor import init_system_monitor
    log("Initializa system monitor", TAG, toFile=False)
    ret = init_system_monitor(app)
    if ret != common.ERR_NONE:
        logE("Init system monitor failed %d" % ret, TAG)
        sys.exit(1)

    from server.storage import init_storage_management
    from server.storage import storageMgr
    ret = init_storage_management(app)
    if ret != common.ERR_NONE:
        logE("Init storage failed %d" % ret, TAG)
        sys.exit(1)


    # [ret, fid] = storageMgr().writeFile(__file__, "test", True)
    # # fid = "zUJATVKtVcz6mspK3IKKpYAK2dOFoGcfvL9yQRgyBhk="
    # storageMgr().readMetaFile(fid)
    # storageMgr().readFile(fid)



    from server import key as key
    from server.key.key_mng import init_key_management
    log("Initializa key management", TAG, toFile=False)
    ret = init_key_management()
    if ret != common.ERR_NONE:
        logE("Init key management failed %d" % ret, TAG)
        sys.exit(1)

    from server.login.user_mng import init_user_management
    log("Initializa UserMgr", TAG, toFile=False)
    ret = init_user_management(app)
    if ret != common.ERR_NONE:
        logE("Init user management failed %d" % ret, TAG)
        sys.exit(1)

    from server.login.login import init_login_management
    log("Initializa login system", TAG, toFile=False)
    ret = init_login_management(app)
    if ret != common.ERR_NONE:
        logE("Init login management failed %d" % ret, TAG)
        sys.exit(1)

    setup(filekey, dbkey)

    appconfig.dbName = dbMgr().getDbName()
    appconfig.saveFile(configPath)

    if (DEBUG): logD(appconfig.toJson(), TAG)
    return app

if __name__ == "__main__":
    configPath=None
    dbkey=db
    filekey=file
    cert_path=None
    cert_key_path=None
    try:
        opts, args = getopt.getopt(sys.argv[1:],PARAM_SHORT_ARG,PARAM_LONG_ARG)
    except getopt.GetoptError:
        printHelp()
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            printHelp()
            sys.exit()
        elif opt in ("-c", "--config"):
            configPath = arg
        elif opt in ("-d", "--dbkey"):
            dbkey = arg
        elif opt in ("-f", "--filekey"):
            filekey = arg
        elif opt in ("--cert"):
            cert_path = arg
        elif opt in ("--key"):
            cert_key_path = arg
    
    flask_app = create_app(db=dbkey, file=filekey, workingdir=ROOT_DIR, appconfigPath=configPath)
    hostname = socket.gethostname()
    
    ssl_context = None
    if cert_path is not None and cert_key_path is not None:
        ssl_context = (cert_path, cert_key_path )
    if (DEBUG): logD("ssl_context %s" % str(ssl_context), TAG)
    
    log("ALL done, start server", TAG)
    log("Start SERVER (%s) with addr http%s://%s:%d, host name %s" % 
        (
            VERSION_NAME, 
            "s" if ssl_context is not None else "", 
            appconfig.get_ip(), 
            appconfig.get_port(), 
            hostname), TAG, 
        toFile = True)

    # TODO: app should get password from argument, 2 passwords: storage, database
    # app.run(host=local_ip, port=port, debug=DEBUG, threaded=True)

    flask_app.run(
        host='0.0.0.0'
        , port=appconfig.get_port()
        , debug=DEBUG
        , threaded=True
        , ssl_context=ssl_context
        )


