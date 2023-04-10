#!/usr/bin/env python
#
#  DB control
#

# http://docs.mongoengine.org/apireference.html#fields
# https://flask-pymongo.readthedocs.io/en/latest/
# https://pythonbasics.org/flask-mongodb/
# http://docs.mongoengine.org/projects/flask-mongoengine/en/latest/

from flask import Flask
from flask_restful import Api, Resource, reqparse
from flask import send_file
from flask import render_template
from flask import request, abort, jsonify, send_from_directory
# from server.app import app

# from server.app import is_debug_db
import os
from server.applog import log
from server.applog import logE
from server.applog import logD
from server import common as common
import json
import traceback
from server import hash as hash
from server import enc as enc

from flask_mongoengine import MongoEngine
from Crypto.Random import get_random_bytes
from server.backup.backup import IBackup
from datetime import datetime
import server.monitor.system_report
from server.app import DEBUG
# Using mongo db
db = MongoEngine()


TAG = "DatabaseMgr"
DB_DIRECTORY_NAME = ".db" # origin/main directory name
DB_META_NAME = "meta" # origin/main directory name

# default dbname in mongodb
DB_NAME = "vfsimplesigning"

#
# Meta data of db
#
class DbMgrMeta:
    keyHashBase64 = "" # hash of final encryption key
    ivStringBase64 = "" # common iv used to encrypt/decrypt data
    saltStringBase64 = "" # common salt, used with key to generate final key

    def __init__(self):
        self.keyHashBase64 = ""
        self.ivStringBase64 = ""
        self.saltStringBase64 = ""
    
    # convert to json string, return json string on success, None otherwise
    def toJson(self):
        try:
            jdata = {
                "keyHashBase64":self.keyHashBase64,
                "ivStringBase64":self.ivStringBase64,
                "saltStringBase64":self.saltStringBase64,
                }
            jstring = json.dumps(jdata)
            return jstring
        except:
            traceback.print_exc()
            logE("Meta db: Convert to json failed", TAG)
            return None
    # parse json string, return ERR_NONE on success, error code otherwise
    def fromJson(self, val):
        try:
            jdata = json.loads(val)
            self.keyHashBase64 = jdata["keyHashBase64"] if "keyHashBase64" in jdata else ""
            self.ivStringBase64 = jdata["ivStringBase64"] if "ivStringBase64" in jdata else ""
            self.saltStringBase64 = jdata["saltStringBase64"] if "saltStringBase64" in jdata else ""
            return common.ERR_NONE
        except:
            traceback.print_exc()
            logE("Meta db: Parse from json failed %s " % val, TAG)
            return common.ERR_EXCEPTION
        

    # get key hash (byte array) by decode base64 to byte arrays
    def getKey(self):
        return common.decodeBase64(self.keyHashBase64)
    
    # get IV (byte array) by decode base64 to byte arrays
    def getIV(self):
        return common.decodeBase64(self.ivStringBase64)
    
    # get salt (byte array) by decode base64 to byte arrays
    def getSalt(self):
        return common.decodeBase64(self.saltStringBase64)

#
# Listener to know if db is changed
#
class IDbListener(object):
    # db password is changed
    def onChangePass(self, oldPass, oldIv, newPass, newIv):
        return common.ERR_NOT_SUPPORT
    
    def getName(self):
        return "unknown"

##########################################################################
# MAIN db management processing
# DB has 2 passwords:
# - user/pass to loging to mongodb
# - password to encrypt some sensitive datat in db
#
##########################################################################
class DatabaseMgr(IBackup):
    key = None
    meta = None
    is_ready = False
    listeners = []

    DB_DIRECTORY = None
    DB_META_FILE = None
    dbName = DB_NAME
    def __init__(self, dbName = DB_NAME):
        self.key = None
        self.is_ready = False
        self.meta = None

        from server.app import getRootDataDir
        self.dbName = dbName if dbName is not None else DB_NAME
        self.DB_DIRECTORY = os.path.join(getRootDataDir(), DB_DIRECTORY_NAME, self.dbName)
        self.DB_META_FILE = os.path.join(self.DB_DIRECTORY, DB_META_NAME)

        if (not os.path.exists(self.DB_DIRECTORY)):
            log("Make DB dir %s" % self.DB_DIRECTORY, TAG)
            os.makedirs(self.DB_DIRECTORY)
        else:
            log("DB dir %s ready" % self.DB_DIRECTORY, TAG)

    def getDbName(self):
        return self.dbName

    # init db
    def initDB(self, app, dbusr, dbpass):
        
        log("Init db with name '%s'" % self.dbName, TAG)

        if dbusr is None or dbpass is None:
            logE("Please login", TAG) # lack of login info
            return common.ERR_REQUIRE_AUTHEN

        # config db
        app.config['MONGODB_SETTINGS'] = {
            'db': self.dbName,
            'host': 'mongodb://localhost/%s' % (self.dbName), # FIXME: localhost is suitable???
            'username':dbusr, # username/password to login to mongodb
            'password':dbpass
        }

        
        try:
            # init db
            db.init_app(app)
            # try to connect
            from server.database import config
            item = config.DbConfig.objects()
        except:
            traceback.print_exc()
            logE("Failed to connect server, not login yet?", TAG)
            return common.ERR_EXCEPTION
    
        # all well
        return common.ERR_NONE
        
    # check if db encryption password is set
    def isPasswordSet(self):
        log("check if password set", TAG)
        from server.database import config

        # get config file, and check if meta file of db already created.
        item = config.DbConfig.objects(status=config.CONFIG_STATUS_READY).first()
        if item is None or item.metaData is None or not os.path.exists(self.DB_META_FILE):
            logE("Not set yet", TAG)
            return False
        log("already set", TAG)
        return True

    # Do setup db
    def setup(self, pwd):
        # logD("base64 %s" % base64.urlsafe_b64encode(key).decode())
        salt = ""
        log("setup", TAG)
        need_set_pass = False
        
        from server.database import config
        # read meta info from db
        item = config.DbConfig.objects(status=config.CONFIG_STATUS_READY).first()
        # TODO: compare meta info from db and in file
        # metaFile not exist, create new one
        if (not os.path.exists(self.DB_META_FILE)):
            meta = item.metaData if item is not None and item.metaData is not None else ""
            if (meta is not None) and len(meta.strip()) > 0:
                ret = common.write_string_to_file(self.DB_META_FILE, meta)
                if (not ret):
                    logE("Write meta from db to file failed", TAG)
                    return common.ERR_FAILED
            else:
                if (DEBUG): logD("not found meta, generate it")
                try:
                    dbMgrMeta = DbMgrMeta()
                    
                    # generate random iv
                    iv = get_random_bytes(enc.AES_BLOCK_SIZE_BYTE)
                    # convert to base64 string
                    dbMgrMeta.ivStringBase64 = common.encodeBase64(iv)

                    # generate random salt
                    salt = get_random_bytes(enc.AES_BLOCK_SIZE_BYTE)
                    # convert to base64 string
                    dbMgrMeta.saltStringBase64 = common.encodeBase64(salt)

                    # calc final key encryption key
                    key = hash.kdfFromString(pwd, dbMgrMeta.saltStringBase64)
                    key_hash = common.encodeBase64(hash.hashVal(key, hash.ALGO_SHA256))

                    dbMgrMeta.keyHashBase64 = key_hash
                    
                    jdata = dbMgrMeta.toJson()
                    # logD(jdata)
                    if (jdata is not None):
                        ret = common.write_string_to_file(self.DB_META_FILE, jdata)
                        if (not ret):
                            logE("Write meta to file failed", TAG)
                            return common.ERR_FAILED
                    else:
                        return common.ERR_FAILED

                    # backup meta file to db
                    if item is None:
                        create_time = datetime.utcnow()
                        item = config.DbConfig(
                            metaData = jdata
                            , status=config.CONFIG_STATUS_READY
                            , created_time = create_time
                            , last_update = create_time
                            )
                        item.save()
                    else:
                        item.update(metaData = jdata, last_update=datetime.utcnow())
                    log("No meta file, need to check to change pass", TAG)
                    need_set_pass = True

                except:
                    traceback.print_exc()
                    logE("Build meta failed", TAG)
                    return common.ERR_EXCEPTION
        else:
            if (DEBUG): logD("found meta, parse it")
            if item is None:
                metaString = common.read_string_from_file(self.DB_META_FILE)

                # save to db if not save yet
                if metaString is not None and len(metaString) > 0:
                    create_time = datetime.utcnow()
                    item = config.DbConfig(
                        metaData = metaString
                        , status = config.CONFIG_STATUS_READY
                        , created_time = create_time
                        , last_update = create_time
                    )
                    item.save()
                #well, if metastring is empty, it'll be clear

        # TODO: check if information in meta file and in db are same

        # well done, let's read meta file ... again... 
        # FIXME: improve this, as it seems to be call twice
        metaString = common.read_string_from_file(self.DB_META_FILE)
        if metaString is None or len(metaString) == 0:
            logE("Read meta failed, not data", TAG)
            return common.ERR_NO_DATA
        
        # parse meta info
        jmeta = DbMgrMeta()
        ret = jmeta.fromJson(metaString)
        if ret != common.ERR_NONE:
            logE("Parse meta failed", TAG)
            return ret

        # FIXME: safe to print info here????
        if (DEBUG): logD("meta %s" % jmeta.toJson(), TAG)

        # calculate key encryption key and key hash
        self.key = hash.kdfFromString(pwd, jmeta.saltStringBase64)
        key_hash = common.encodeBase64(hash.hashVal(self.key, hash.ALGO_SHA256))

        # check if key are matched
        if (key_hash == jmeta.keyHashBase64):
            log("Key encryption Key OK", TAG)
        else:
            logE("key not match, expect %s, real %s" % (key_hash, jmeta.keyHashBase64), TAG)
            return common.ERR_NOT_MATCH

        if need_set_pass:
            ret = self.changePass(None, None, None, self.key, jmeta.getSalt(), jmeta.getIV(), False)
            if ret != common.ERR_NONE:
                return ret
        
                
        self.meta = jmeta

        # clean up temp file
        # self.checkToClearTemp()

        # all well done, hope so
        self.is_ready = True

        log("db is ready to use", TAG)
        return common.ERR_NONE

    # change db encryption password
    def changePass(self, oldKey, oldSalt, oldIV, newKey, newSalt, newIv, updateMeta = True):
        log("changePass", TAG)
        for listener in self.listeners:
            if listener is not None:
                log("call %s to change pass" % listener.getName(), TAG)
                ret = listener.onChangePass(oldKey, oldIV, newKey, newIv)
                if (ret != common.ERR_NONE):
                    logE("%s change pass FAILED" % listener.getName(), TAG)
                    return ret
        
        if updateMeta:
            try:
                dbMgrMeta = DbMgrMeta()
                # convert to base64 string
                dbMgrMeta.ivStringBase64 = common.encodeBase64(newIv)

                # convert to base64 string
                dbMgrMeta.saltStringBase64 = common.encodeBase64(newSalt)

                # calc final key encryption key
                key_hash = common.encodeBase64(hash.hashVal(newKey, hash.ALGO_SHA256))

                dbMgrMeta.keyHashBase64 = key_hash
                
                jdata = dbMgrMeta.toJson()
                # logD(jdata)
                if (jdata is not None):
                    ret = common.write_string_to_file(self.DB_META_FILE, jdata)
                    if (not ret):
                        logE("Write meta to file failed", TAG)
                        return common.ERR_FAILED
                else:
                    return common.ERR_FAILED

            except:
                traceback.print_exc()
                logE("Build meta failed", TAG)
                return common.ERR_EXCEPTION

        return common.ERR_NONE

    # api to other to register listener db chagne status
    def registerListener(self, listener):
        self.listeners.append(listener)

    # encrypt data to be saved to db, using db encryption password
    def encryptData2Base64(self, plain, key=None, iv=None):
        if (DEBUG): logD("encryptData2Base64", TAG)
        # logD(plain.hex(), TAG)
        # if key is not None:
        #     if (DEBUG): logD("key %s" % key.hex(), TAG)
        # if iv is not None:
        #     if (DEBUG): logD("iv %s" % iv.hex(), TAG)
        # if self.key is not None:
        #     if (DEBUG): logD("self.key %s" % self.key.hex(), TAG)
        # if self.meta is not None and self.meta.getIV() is not None:
        #     if (DEBUG): logD("meta.getIV %s" % self.meta.getIV(), TAG)
        if key is None and self.key is None:
            raise ValueError("Failed to encrypt. DB Not ready yet")
        if plain is None or len(plain) == 0:
            raise ValueError("Failed to encrypt. Invalid argument")
        return enc.encrypt2Base64(None, plain, self.key if key is None else key, self.meta.getIV() if iv is None else iv)

    # encrypt data to be saved to db, using db encryption password
    def encryptDataString2Base64(self, plain, key=None, iv=None):
        if (DEBUG): logD("encryptDataString2Base64", TAG)
        # logD(plain, TAG)
        try:
            if plain is not None and len(plain) > 0:
                return self.encryptData2Base64(bytes(plain, 'utf-8'), key, iv)
            else:
                logE("empty data to encrypt", TAG)
                return None
        except:
            traceback.print_exc()
            logE("Exception occur when encrypt data", TAG)
            return None
    
    # decrdypt data to be saved to db, using db encryption password
    def decryptDataFromBase64(self, cipher, key=None, iv=None):
        if (DEBUG): logD("decryptDataFromBase64", TAG)
        # logD(cipher, TAG)
        if key is None and self.key is None:
            raise ValueError("Failed to decrypt. DB Not ready yet")
        if cipher is None or len(cipher) == 0:
            raise ValueError("Failed to decrypt. Invalid argument")
        return enc.decryptFromBase64(None, cipher, self.key if key is None else key, self.meta.getIV() if iv is None else iv)
        

    # return byte arrays
    def hashWithKey(self, data):
        import hashlib
        return hashlib.pbkdf2_hmac('sha256', self.key, data, 10)

    def reEncryptData(self, cipher, oldKey, oldIv = None, newKey = None, newIv = None):
        # if not self.is_ready:
        #     raise ValueError("Failed to encrypt. DB Not ready yet")
        if (DEBUG): logD("reEncryptData", TAG)
        if cipher is None or len(cipher) == 0:
            return ""
        plain = self.decryptDataFromBase64(cipher, oldKey, oldIv) if oldKey is not None else cipher
        return self.encryptDataString2Base64(plain, newKey, newIv)
        
    # do backup db
    def doBackup(self, backupDir):
        log("doBackup", TAG)
        # TODO: implement this
        from server.database.account import Account
        for item in Account.objects():
            if (DEBUG): logD(item.to_json(), TAG)
        return common.ERR_NONE

#####################################################################

g_dbMgr = None

def dbMgr():
    global g_dbMgr
    if g_dbMgr is None:
        raise ValueError("DB not init yet")
    return g_dbMgr

#
# Init datablase
#
def init_database(application, url, port, dbusr=None, dbpass=None, dbName = None):
    if (DEBUG): logD("init_database %s:%d, name: %s" %(url, port, dbName), TAG)
    # TODO check precondition like database, mongodb, etc.
    
    global g_dbMgr
    if g_dbMgr is None:
        g_dbMgr = DatabaseMgr(dbName)

    ret = g_dbMgr.initDB(application, dbusr, dbpass)
    if (ret == common.ERR_NONE):
        log("Init DB ok", TAG)
        server.monitor.system_report.sysReport().setStatus(
                server.monitor.system_report.MODULE_NAME_DB,
                server.monitor.system_report.MODULE_STATUS_INIT, # db is initied, but not ready to use
                "init ok"
                )
    else:
        logE("init DB failed %d (%s)" % (ret, common.get_err_msg(ret)), TAG, True)
            
    return ret

# Setup datablase
def setup_database(application, password = None, auto_set_pass = False):
    log("setup_database", TAG)

    # setup encryption password
    try:
        if (dbMgr().isPasswordSet() or auto_set_pass):
            ret = dbMgr().setup(password)
        else:
            logE("not set password yet", TAG)
            ret = common.ERR_NOT_READY

        # register to backup event
        from server.backup.backup_mgr import backupMgr
        backupMgr().registerBackup(dbMgr())

    except:
        traceback.print_exc()
        logE("Exception occur when setup db", TAG)
        ret = common.ERR_EXCEPTION

    log("setup_database result %d" % ret, TAG)
    if ret == common.ERR_NONE:
        server.monitor.system_report.sysReport().setStatus(
            server.monitor.system_report.MODULE_NAME_DB,
            server.monitor.system_report.MODULE_STATUS_READY, #well done, ready to use
            "db ready"
            )
    else:
        server.monitor.system_report.sysReport().setStatus(
            server.monitor.system_report.MODULE_NAME_DB,
            server.monitor.system_report.MODULE_STATUS_FAILED, # something wrong
            "db setup failed %d" % ret
            )
        # TODO: should clean up something??? i.e. unregister backup event
    
    return ret
    


