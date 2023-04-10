#!/usr/bin/env python
#
#  KEY MANAGEMENT
#


from flask import Flask
from flask_restful import Api, Resource, reqparse
from flask import send_file
from flask import render_template
from flask import request, abort, jsonify, send_from_directory
# from server.app import app
from server.app import getRootDataDir
from server.app import KEEP_OUTPUT_FILE
from server.app import DEBUG
from server.app import is_debug_db
import os
from server.applog import log
from server.applog import logE
from server.applog import logD
from server.app import get_resp
from server import common as common
import traceback
import shutil
# from server.database.key import Key
from server.database.key import KeyFile
from server.database.key import KEY_STATUS_NOT_READY
from server.database.key import KEY_STATUS_READY
from server.database.key import KEY_STATUS_DELETED
from datetime import datetime
from server.database.key_info import KeyInfo
from server.database.key_info import KeyFileMeta
from flask_login import login_required
from server.database.key import KEY_DATA_TYPE_FILE
from server.storage import storageMgr
from server.storage import IStorageListener
# import server.database
from server.database.key import Key
# from server.database.db_mgr import IDbListener
import server.database.db_mgr
from server import database as database

from server.app import getRootDownloadDir
# from server.database.db_mgr import dbMgr
import ast
import tempfile
from server import enc
from server.app import DEBUG

TAG = "KeyMgr"

#folder to store key file
KEY_FOLDER_NAME = ".key"

# ABS folder path.
# USED WHEN RUN TIME ONLY, SHOULD NOT STORE PERSISTANTLY
KEY_DIRECTORY = os.path.join(getRootDataDir(), KEY_FOLDER_NAME)

KEY_DOWNLOAD_DIR = os.path.join(getRootDownloadDir(), "keydl")

POLICY_ACTION_DOWNLOAD = "download"
POLICY_ACTION_DELETE = "delete"

POLICY_ACTION_LIST = [POLICY_ACTION_DOWNLOAD]
# get FULL PATH of key
# USED WHEN RUN TIME ONLY, SHOULD NOT STORE PERSISTANTLY
def getKeyDir():
    return KEY_DIRECTORY

# Get relative path
def getRelativeKeyDir():
    return KEY_FOLDER_NAME

class IKeyChangeListener(object):

    def getName(self):
        return None

    def onKeyDeleted(self, key_info):
        if (DEBUG): logD("onKeyDeleted %s" % self.getName(), TAG)
        return common.ERR_NONE

class KeyMgr(database.db_mgr.IDbListener, IStorageListener):
    from server.database.key import Key
    from server.database.key import KeyFile
    from server.database.key import KEY_STATUS_NOT_READY
    from server.database.key import KEY_STATUS_READY
    from server.database.key import KEY_STATUS_DELETED
    from server.database.key_info import KeyInfo
    from server.database.key_info import KeyFileMeta
    from server.database.key import KEY_DATA_TYPE_FILE

    listeners = []

    # from server.database.key import IDbListener
    # from server.database.db_mgr import dbMgr
    def __init__(self):
        database.db_mgr.dbMgr().registerListener(self)
        self.listeners = []
    

    def registerListener(self, listener):
        if listener is not None and listener.getName() is not None:
            log("Register listener %s" % listener.getName(), TAG)
            self.listeners.append(listener)
        else:
            logE("Register listener failed, not set name?", TAG)
            return common.ERR_FAILED

    def onChangePass(self, oldKey, oldIv, newKey, newIv):
        if (DEBUG): logD("onChangePass", TAG)
        
        items = Key.objects()
        for item in items:
            if (DEBUG): logD("Change pass for key id %s" % item.id)

            if item.encrypted and oldKey is None:
                logE("Failed to change pass, key's data is encrypted, but no old pass set", TAG)
                return common.ERR_INVALID_DATA
            
            item.name = database.db_mgr.dbMgr().reEncryptData(item.name, oldKey, oldIv, newKey, newIv)
            item.tag = database.db_mgr.dbMgr().reEncryptData(item.tag, oldKey, oldIv, newKey, newIv)
            item.alg = database.db_mgr.dbMgr().reEncryptData(item.alg, oldKey, oldIv, newKey, newIv)
            item.hint = database.db_mgr.dbMgr().reEncryptData(item.hint, oldKey, oldIv, newKey, newIv)
            item.data = database.db_mgr.dbMgr().reEncryptData(item.data, oldKey, oldIv, newKey, newIv)
            item.history = database.db_mgr.dbMgr().reEncryptData(item.history, oldKey, oldIv, newKey, newIv)
            keyFiles = []
            if (item.files is not None):
                for keyfile in item.files:
                    if (keyfile is not None):
                        if (keyfile.name is not None and len(keyfile.name) > 0):
                            keyfile.name = database.db_mgr.dbMgr().reEncryptData(keyfile.name, oldKey, oldIv, newKey, newIv)

                            if (keyfile.path is not None and len(keyfile.path) > 0):
                                keyfile.path = database.db_mgr.dbMgr().reEncryptData(keyfile.path, oldKey, oldIv, newKey, newIv)

                            if (keyfile.fid is not None and len(keyfile.fid) > 0):
                                keyfile.fid = database.db_mgr.dbMgr().reEncryptData(keyfile.fid, oldKey, oldIv, newKey, newIv)
                            keyFiles.append(keyfile)
            item.files = keyFiles
                                
            item.encrypted = True
            item.save()
        
        return common.ERR_NONE

    def getName(self):
        return "KeyMgr"

    # Check if ACTIVE key exists, using key name + project + model
    # RETURN common.ERR_NOT_FOUND if not found, ERR_EXISTED if exist, else error code
    def is_key_exist(self, key_info, tools=None, keytools=None):
        #TODO: should caching it to enhance performance? (take care of sync issue between  cache and database)
        if (DEBUG): logD("is_key_name_exist", TAG)
        if (key_info is None):
            logE("key_info invalid", TAG)
            return common.ERR_INVALID_DATA
        
        # search key in db
        if (DEBUG): logD("Search key name %s project %s model %s" % (key_info.name,key_info.project,key_info.model), TAG)
        try:
            projects = common.string2List(key_info.project)
            models = common.string2List(key_info.model)
            tools = tools if tools is not None else common.string2List(key_info.target_tool)
            keytools = keytools if keytools is not None else common.string2List(key_info.target_keytool)
            if (projects is None) or (models is None) or (tools is None) or (keytools is None):
                if (DEBUG): logD("projects %s "  % str(projects), TAG)
                if (DEBUG): logD("models %s "  % str(models), TAG)
                if (DEBUG): logD("tools %s "  % str(tools), TAG)
                if (DEBUG): logD("keytools %s "  % str(keytools), TAG)
                logE("not found project/model/tools/keytools", TAG)
                return common.ERR_INVALID_DATA
            if (DEBUG): logD("projects %s" % str(projects), TAG)
            if (DEBUG): logD("models %s" % str(models), TAG)
            if (DEBUG): logD("tools %s" % str(tools), TAG)
            if (DEBUG): logD("keytools %s" % str(keytools), TAG)
            enc_name = database.db_mgr.dbMgr().encryptDataString2Base64(key_info.name)
            if enc_name is None or len(enc_name) == 0:
                logE("Failed to encrypt name", TAG)
                return common.ERR_INVALID_ARGS
            # _key = Key.objects(name=key_info.name, project=key_info.project, model=key_info.model, status=KEY_STATUS_READY).first()
            keys = Key.objects(name=enc_name, status=KEY_STATUS_READY)
            if keys is not None and len(keys) > 0:
                for key in keys:
                    dbprojects = common.string2List(key.project)
                    dbmodels = common.string2List(key.model)
                    dbtools = common.string2List(key.target_tool)
                    dbkeytools = common.string2List(key.target_keytool)
                    if (DEBUG): logD("dbprojects %s" % str(dbprojects), TAG)
                    if (DEBUG): logD("dbmodels %s" % str(dbmodels), TAG)
                    if (DEBUG): logD("dbtools %s" % str(dbtools), TAG)
                    if (DEBUG): logD("dbkeytools %s" % str(dbkeytools), TAG)
                    if (dbprojects is None) and (dbmodels is None) and (dbtools is None) and (dbkeytools is None):
                        return common.ERR_NOT_FOUND
                    else:
                        foundPrj = False
                        foundModel = False
                        foundTool = False
                        foundKeyTool = False
                        for prj1 in projects:
                            for prj2 in dbprojects:
                                if prj1 == prj2 or prj2 == common.ANY_INFO:
                                    foundPrj = True
                                    break
                            if foundPrj:
                                break
                        
                        for mod1 in models:
                            for mod2 in dbmodels:
                                if mod1 == mod2 or mod2 == common.ANY_INFO:
                                    foundModel = True
                                    break
                            if foundModel:
                                break

                        for item1 in tools:
                            for item2 in dbtools:
                                if item1 == item2:
                                    foundTool = True
                                    break
                            if foundTool:
                                break

                        for item1 in keytools:
                            for item2 in dbkeytools:
                                if item1 == item2:
                                    foundKeyTool = True
                                    break
                            if foundKeyTool:
                                break

                        if foundModel and foundPrj and foundTool and foundKeyTool:
                            return common.ERR_EXISTED
        except:
            traceback.print_exc()
            return common.ERR_EXCEPTION
        return common.ERR_NOT_FOUND

    # get ACTIVE key basing on key id, return key info, None on error
    def get_key(self, key_id):
        if (DEBUG): logD("get_key %s" % key_id, TAG)
        if (key_id is None or len(str(key_id)) == 0):
            logE("key_id invalid", TAG)
            return None
        # search key in db
        if (DEBUG): logD("Search key id %s" % (key_id), TAG)
        # _key = Key.objects(id=key_id,status=not KEY_STATUS_DELETED).first()
        _key = Key.objects(id=key_id,status__ne=KEY_STATUS_DELETED).first()

        # _key = Key.find(
        #     {id:key_id,status:{ $ne: KEY_STATUS_DELETED }}).first()
        if (_key is not None):
            if (DEBUG): logD("Found key %s" % key_id, TAG)
            return KeyInfo(keyDB=_key) # convert key in db to keyinfo
        
        if (DEBUG): logD("Not Found key %s" % key_id, TAG)
        return None

    # get ACTIVE key basing on name, project and model, return key info, None on error
    def get_key_by_name(self, name, project, model, tool, keytool):
        if (DEBUG): logD("get_key_by_name %s project %s model %s" % (name,project, model), TAG)
        if (((name is None) or (len(name) == 0)) or 
            # ((project is None) or (len(project) == 0)) or 
            # ((model is None) or (len(model) == 0))  or 
            ((tool is None) or (len(tool) == 0))  or 
            ((keytool is None) or (len(keytool) == 0)) 
            ):
            logE("name/project/model invalid", TAG)
            return None
        if (DEBUG): logD("Search key name %s" % (name), TAG)
        try:
            enc_name = database.db_mgr.dbMgr().encryptDataString2Base64(name)
            # _key = Key.objects(name=enc_name, project=project, model=model, status=KEY_STATUS_READY).first()
            # if (_key is not None):
            #     if (DEBUG): logD("Found key %s" % name)
            #     return KeyInfo(keyDB=_key) # convert key in db to keyinfo
            keys = Key.objects(name=enc_name, status=KEY_STATUS_READY)
            if (DEBUG): logD("searched %d key" % len(keys), TAG)
            foundkey = None
            if keys is not None and len(keys) > 0:
                for key in keys:
                    if (DEBUG): logD("key %s" % key.toString(), TAG)
                    dbprojects = common.string2List(key.project)
                    dbmodels = common.string2List(key.model)
                    dbtools = common.string2List(key.target_tool)
                    dbkeytools = common.string2List(key.target_keytool)
                    if (DEBUG): logD("dbprojects %s" % str(dbprojects), TAG)
                    if (DEBUG): logD("dbmodels %s" % str(dbmodels), TAG)
                    if (DEBUG): logD("dbtools %s" % str(dbtools), TAG)
                    if (DEBUG): logD("dbkeytools %s" % str(dbkeytools), TAG)
                    found = self.matchKey(project, model, tool, keytool, dbprojects, dbmodels, dbtools, dbkeytools)
                    if found:
                        foundkey = key
                        break

            if (foundkey is not None):
                if (DEBUG): logD("Found key %s" % name, TAG)
                return KeyInfo(keyDB=foundkey) # convert key in db to keyinfo
            if (DEBUG): logD("Not Found key %s" % name, TAG)
        except:
            traceback.print_exc()
        return None

    def get_default_key2(self, projects=[], models=[], tools=[], keytools=[]):
        if (DEBUG): logD("get_default_key2", TAG)
        if (DEBUG): logD("projects %s" % str(projects), TAG)
        if (DEBUG): logD("models %s" % str(models), TAG)
        if (DEBUG): logD("tools %s" % str(tools), TAG)
        if (DEBUG): logD("keytools %s" % str(keytools), TAG)
        keys = Key.objects(isdefault=True, status=KEY_STATUS_READY)

        if keys is not None and len(keys) > 0:
            for key in keys:
                foundPrj = False
                foundModel = False
                foundTool = False
                foundKeyTool = False
                for item in projects:
                    if key.project.find("'%s'" % item) >= 0 or key.project.find("'%s'" % common.ANY_INFO) >= 0:
                        foundPrj = True
                        break
                
                for item in models: 
                    if key.model.find("'%s'" % item) >= 0 or key.model.find("'%s'" % common.ANY_INFO) >= 0:
                        foundModel = True
                        break
                    
                for item in tools:
                    if key.target_tool.find("'%s'" % item) >= 0:
                        foundTool = True
                        break

                for item in keytools:
                    if key.target_keytool.find("'%s'" % item) >= 0:
                        foundKeyTool = True
                        break
                
                if foundPrj and foundModel and foundTool and foundKeyTool:
                    if (DEBUG): logD("found one")
                    keyinf = KeyInfo(keyDB=key) 
                    if (DEBUG): logD("keyinf %s" % keyinf.toString(), TAG)
                    return keyinf
        
        if (DEBUG): logD("Not found any key")
        return None


    def get_default_key(self, project, model, tool, keytool):
        if (DEBUG): logD("get_default_key %s project %s model %s" % (project, model, tool), TAG)
        if (
            ((project is None) or (len(project) == 0)) or 
            ((model is None) or (len(model) == 0)) or 
            ((tool is None) or (len(tool) == 0)) or
            ((keytool is None) or (len(keytool) == 0))
            ):
            logE("tool/project/model invalid", TAG)
            return None
        try:
            keys = Key.objects(isdefault=True, status=KEY_STATUS_READY)
            foundkey = None
            if keys is not None and len(keys) > 0:
                for key in keys:
                    dbprojects = common.string2List(key.project)
                    dbmodels = common.string2List(key.model)
                    dbtools = common.string2List(key.target_tool)
                    dbkeytools = common.string2List(key.target_keytool)
                    if (DEBUG): logD("dbprojects %s" % str(dbprojects), TAG)
                    if (DEBUG): logD("dbmodels %s" % str(dbmodels), TAG)
                    if (DEBUG): logD("dbtools %s" % str(dbtools), TAG)
                    if (DEBUG): logD("dbkeytools %s" % str(dbkeytools), TAG)
                    if ((dbprojects is None )
                        and (dbmodels is None)
                        and (dbtools is None)
                        and (dbkeytools is None)
                        ):
                        return None
                    else:
                        found = self.matchKey(project, model, tool, keytool, dbprojects, dbmodels, dbtools, dbkeytools)
                        if found:
                            foundkey = key
                            break
            if (foundkey is not None):
                if (DEBUG): logD("Found default key", TAG)
                return KeyInfo(keyDB=foundkey) # convert key in db to keyinfo
            if (DEBUG): logD("Not Found default key", TAG)
        except:
            traceback.print_exc()
        return None

    def matchKey(self, project, model, tool, keytool, projects, models, tools, keytools):
        if (DEBUG): logD("matchKey project %s model %s tool %s keytools %s " % (project, model, tool, keytool), TAG)
        if (DEBUG): logD("projects %s" % str(projects), TAG)
        if (DEBUG): logD("models %s" % str(models), TAG)
        if (DEBUG): logD("tools %s" % str(tools), TAG)
        if (DEBUG): logD("keytools %s" % str(keytools), TAG)
        foundkey = False
        foundPrj = False
        foundModel = False
        foundTool = False
        foundKeyTool = False
        if project is not None and len(project) > 0 and projects is not None and len(projects) > 0:
            for item in projects:
                if project == item or item == common.ANY_INFO:
                    foundPrj = True
                    break
        else:
            foundPrj = True
        
        if model is not None and len(model) > 0 and models is not None and len(models) > 0:
            for item in models:
                if model == item or item == common.ANY_INFO:
                    foundModel = True
                    break
        else:
            foundModel = True
        
        if tool is not None and len(tool) > 0 and tools is not None and len(tools) > 0:
            for item in tools:
                if item == tool:
                    foundTool = True
                    break
        else:
            foundTool = True
        
        if keytool is not None and len(keytool) > 0 and keytools is not None and len(keytools) > 0:
            for item in keytools:
                if item == keytool:
                    foundKeyTool = True
                    break
        else:
            foundKeyTool = True
        
        if (DEBUG): logD("foundModel %d" % foundModel, TAG)
        if (DEBUG): logD("foundPrj %d" % foundPrj, TAG)
        if (DEBUG): logD("foundTool %d" % foundTool, TAG)
        if (DEBUG): logD("foundKeyTool %d" % foundKeyTool, TAG)
        if foundModel and foundPrj and foundTool and foundKeyTool:
            foundkey = True
        if (DEBUG): logD("foundkey %s" % foundkey, TAG)
        return foundkey

    # update key status
    def update_key_status(self, key_id, status):
        if (DEBUG): logD("update_key_status %d" % status, TAG)
        if (DEBUG): logD("Search key key_id %s" % key_id, TAG)
        # TODO: check status/id param
        ret = common.ERR_NONE
        # search key first
        _key = Key.objects(id=key_id).first()

        if (_key is None):
            logE("Key not found", TAG)
            return common.ERR_NOT_FOUND
        try:
            keyinfo = KeyInfo(keyDB=_key)
            ret = keyinfo.updateStatus(status = status, updateDB=True)
            # _key.update(status = status)
        except:
            traceback.print_exc()
            logE("Update key status failed", TAG)
            return common.ERR_FAILED
        
        return ret

    # get full path of key, should be used in RUN-TIME only
    def get_full_key_path(self, path):
        return os.path.join(getRootDataDir(), path)

    # IMPORT key to db
    def import_key(self, key_info_org, access_token, workingdir, keytoolname = None, keyfilelist=None, tools=None, keytools=None):
        log("import_key from %s" % access_token, TAG, True)
        if (key_info_org is None) or workingdir is None:
            return [common.ERR_INVALID_ARGS, "invalid arg"]

        if (not key_info_org.validate(incsignature = False)): # validate key data
            logE("invalid key data", TAG, True)
            key_info_org.cleanup(True)
            return [common.ERR_INVALID_DATA, "invalid key data"]

        import copy
        if (DEBUG): logD("Deep copy key_info_org %s" % key_info_org.toString())
        key_info = copy.deepcopy(key_info_org)
        if keytools is not None:
            key_info.target_keytool = str(keytools)
        if tools is not None:
            key_info.target_tool = str(tools)

        
        if (DEBUG): logD("key_info %s" % key_info.toString())
        files = keyfilelist if keyfilelist is not None else key_info.files
        # Validate key data with sign tool
        # 2021/04/19: remove this processing, moved checking to import processing of key tool
        # log("Validate with signing tool", TAG)
        # tmpFnam = common.getRandomString(4)
        # tmpFolder = os.path.join(workingdir, tmpFnam)
        # logD("tmpFolder %s" % tmpFolder)
        # ret = common.ERR_FAILED
        # if not os.path.exists(tmpFolder):
        #     common.mkdir(tmpFolder)
        # if files is not None and len(files) > 0:
        #     log("Copy key files of key %s to key folder" % key_info.name)
        #     for fname, path in files.items():
        #         if common.isZipFile(path):
        #             common.unzip_file(path, tmpFolder)
        #         else:
        #             shutil.copy(path, tmpFolder)

        # invalidtool = None
        # tools = key_info.getTools()
        # ret = common.ERR_NONE
        # msg = ""
        # if (tools is not None):
        #     from server.sign.signfactory import SignFactory
        #     for tool in tools:
        #         sign_tool = SignFactory.get_sign_tool_by_name(tool)
        #         if sign_tool is not None:
        #             [ret, msg] = sign_tool.validate_key(tmpFolder, key_info.pwd) # validate key data
        #             if ret != common.ERR_NONE:
        #                 logE(msg, TAG)
        #                 invalidtool = tool
        #                 break
        #         else:
        #             logE("Unsupport tool '%s'" % tool, TAG, True)
        #             key_info.cleanup(True)
        #             common.rmdirs(tmpFolder)
        #             return [common.ERR_INVALID_DATA, "Unsupport tool '%s'" % tool]

        #     if invalidtool is not None:
        #         logE("Key info not suitable for sign tool '%s'" % invalidtool, TAG, True)
        #         key_info.cleanup(True)
        #         common.rmdirs(tmpFolder)
        #         return [common.ERR_INVALID_DATA, "Key info not suitable for sign tool '%s', %s" % (invalidtool, msg)]
        # else:
        #     logE("No tool is selected", TAG, True)
        #     key_info.cleanup(True)
        #     common.rmdirs(tmpFolder)
        #     return [common.ERR_INVALID_DATA, "not found tool"]
        
        # common.rmdirs(tmpFolder)

        if (DEBUG): logD("Search key name %s" % key_info.name, TAG)
        if keytools is not None:
            if (DEBUG): logD("keytools %s" % str(keytools), TAG)

        # check if key exist first
        is_exist = self.is_key_exist(key_info)
        if (is_exist != common.ERR_NOT_FOUND):
            # key_info.cleanup()
            return [is_exist, "key %s existed" % key_info.name]

        # FIXME: check this
        salt = "%s" % common.get_randint()
        created_time = datetime.utcnow()
        last_update_time = created_time

        # history = "Create %s at time %s;\n" % (key_info.name,created_time)

        key_info.created_time = created_time
        key_info.last_update_time = last_update_time
        key_info.appendHistory("Created %s" % (key_info.name))

        # make key to save on db
        # newKey = Key(
        #     name = key_info.name,
        #     tag = key_info.tag,
        #     alg = key_info.alg,
        #     # pwd = key_info.pwd, # don't store to db, store to encrypted storage
        #     data = key_info.data,
        #     data_type = key_info.data_type,
        #     key_source = key_info.key_source,
        #     # salt = "%s" % salt, # don't store to db, store to encrypted storage
        #     hint = key_info.hint,
        #     project = key_info.project if key_info.project is not None else "", # FIXME PLEASE
        #     model = key_info.model if key_info.model is not None else "", # FIXME PLEASE
        #     created_time = created_time,
        #     last_update_time = last_update_time,
        #     history = history
        #     )
        newKey = key_info.toKeyDB()
        
        if newKey is None:
            return [common.ERR_FAILED, "save key to db failed"]

        if (DEBUG): logD("new key %s" % newKey.toString())
        
        try:
            newKey.save() # save to db
        except:
            traceback.print_exc()
            logE("Save key %s failed" % key_info.name, TAG, True)
            key_info.cleanup()
            return [common.ERR_FAILED, "save key failed"]

        # get id generated by db
        newkey_id = "%s" % newKey.id
        if (DEBUG): logD("newKey id %s" % newkey_id)
        key_info.id = newKey.id
        try:
            # Key saved to DB, but still in not ready phase
            # TODO: Risk of dup key name + project + model due to this waiting processing

            # key if info is file, copy key files to key folder
            if (key_info.data_type == KEY_DATA_TYPE_FILE):
                if (DEBUG): logD("Copy key file")
                keyFiles = []
                
                # prepare key folder for this
                relative_key_folder = os.path.join(getRelativeKeyDir(), newkey_id)
                full_key_folder = os.path.join(getRootDataDir(), relative_key_folder)

                common.mkdir(full_key_folder)
                if (DEBUG): logD("relative_key_folder %s " % relative_key_folder)
                if (DEBUG): logD("full_key_folder %s " % full_key_folder)
                if key_info.fids is not None and len(key_info.fids) > 0:
                    for fname, fid in key_info.fids.items():
                        if (DEBUG): logD("add fname %s, fid %s" % (fname, fid))
                        meta = storageMgr().readMetaFile(fid)
                        metadata = database.db_mgr.dbMgr().encryptDataString2Base64(meta.toJson()) if meta is not None else ""
                        keyfile = KeyFile(
                                    name = database.db_mgr.dbMgr().encryptDataString2Base64(fname), 
                                    fid = database.db_mgr.dbMgr().encryptDataString2Base64(fid), 
                                    metadata = metadata)
                        keyFiles.append(keyfile)
                # try to copy file
                if files is not None and len(files) > 0:
                    log("Copy key files of key %s to key folder" % key_info.name)
                    for fname in files:
                        # key_file = os.path.join(relative_key_folder, fname) # relative path
                        # full_key_file = os.path.join(ROOT_DIR, key_file) # full path

                        # logD("copy from %s to %s" % (key_info.files[fname], full_key_file))
                        
                        # shutil.copy(key_info.files[fname], full_key_file)


                        # # TODO: encrypt key files data
                        # keyfile = KeyFile(name = fname, path=key_file, fid=fid)
                        keyMeta = KeyFileMeta()
                        keyMeta.id = newkey_id
                        keyMeta.name = key_info.name
                        keyMeta.password = key_info.pwd
                        keyMeta.salt = salt
                        keyMeta.fname = fname

                        if (DEBUG): logD("encrypt from %s" % (files[fname]), TAG)
                        [ret, fid] = storageMgr().writeFile(
                            files[fname], 
                            newkey_id, 
                            keyMeta.toJson())
                        if (DEBUG): logD("Encrypt ret %d" % ret, TAG)
                        if (ret == common.ERR_NONE) and (fid is not None):
                            if (DEBUG): logD("Encrypt ok, fid %s" % fid)
                            meta = storageMgr().readMetaFile(fid)
                            metadata = database.db_mgr.dbMgr().encryptDataString2Base64(meta.toJson()) if meta is not None else ""
                            keyfile = KeyFile(
                                        name = database.db_mgr.dbMgr().encryptDataString2Base64(fname), 
                                        fid = database.db_mgr.dbMgr().encryptDataString2Base64(fid), 
                                        metadata = metadata)
                            keyFiles.append(keyfile)

                            # files is None, mean using files in keyinfo
                            # FIXME if this is not good implementation
                            if keyfilelist is None: 
                                if (DEBUG): logD("Remove temp file %s" % key_info.files[fname])
                                os.remove(key_info.files[fname])
                                # key_info.files[fname] = key_file # save relative path only.
                                key_info.files[fname] = None
                            
                            key_info.fids[fname] = fid
                        else:
                            logE("failed to store file %s to encrypted storage" % fname, TAG)
                            raise ValueError("failed to store file to encrypted storage")
                        
                    
                # update file info of key to DB
                if (DEBUG): logD("Update key file info")
                newKey.update(files = keyFiles)

                # write key info, just for informative
                if (DEBUG): logD("Write key info to file")
                # finf = os.path.join(full_key_folder, "%s_%s" % (newKey.name, newkey_id))
                # common.write_to_file(finf, bytes(key_info.toString(), 'utf-8'))
                # [ret, meta, fid] = storageMgr().writeBuf2File(bytes(key_info.toString(), 'utf-8'), finf)
                meta = key_info.getMeta()
                if (meta is not None):
                    # common data, no need to encrypt, can be used to get info from db when need
                    finf = os.path.join(full_key_folder, "%s_%s" % (newKey.name, newkey_id))
                    # [ret, meta, fid] = storageMgr().writeBuf2File(bytes(key_info.toString(), 'utf-8'))
                    common.write_to_file(finf, bytes(meta, 'utf-8'))
                else:
                    logE("failed to generate meta for file %s" % fname, TAG)
                    raise ValueError("failed to generate meta for file")
            else:
                if (DEBUG): logD("Key is data")
            log("update key %s to KEY_STATUS_READY" % (newKey.name))

            # chagne status to READY
            # TODO: should check if anyone added new key with same key name + project + model before
            # signature = key_info.calcSignature(newKey)
            # newKey.update(status = KEY_STATUS_READY)
        except:
            traceback.print_exc()
            logE("Update key failed")
            # TODO: clean data?
            # key_info.cleanup()
            return [common.ERR_FAILED, "update key failed, exception occur"]

        key_info.id = newkey_id
        key_info.keyondb = newKey
        ret = key_info.updateStatus(KEY_STATUS_READY, True)
        log("Save key %s, db id %s" % (key_info.name, key_info.id), toFile=True)
        #TODO: DO BACKUP DATABASE
        #TODO: DO BACKUP KEY FILES
        # ALL well
        return [ret, ""]

    # conver key in db to key_info
    # Mar 26: moved to key_info 
    # def key2keyinfo(key):
    #     key_info = KeyInfo()
    #     key_info.id = key.id
    #     key_info.name = key.name
    #     key_info.tag = key.tag
    #     key_info.alg = key.alg
    #     key_info.data_type = key.data_type
    #     key_info.key_source = key.key_source
    #     key_info.hint = key.hint
    #     key_info.created_time = key.created_time
    #     key_info.last_update_time = key.last_update_time
    #     key_info.history = key.history
    #     key_info.status = key.status
    #     key_info.project = key.project
    #     key_info.model = key.model
    #     key_info.keyondb = key
    #     if (key.files is not None):
    #         for keyfile in key.files:
    #             if (keyfile is not None):
    #                 if (keyfile.name is not None and len(keyfile.name) > 0):                    
    #                     if (keyfile.path is not None and len(keyfile.path) > 0):
    #                         key_info.files[keyfile.name] = keyfile.path
    #                     if (keyfile.fid is not None and len(keyfile.fid) > 0):
    #                         key_info.fids[keyfile.name] = keyfile.fid
    #     return key_info

    # get all ready key, return empty list if error
    def get_all_keys(self, project = None, model = None, tool = None, keytool = None, includeDelete=False):
        log("get_all_keys", TAG)
        log("project %s" % project, TAG)
        log("model %s" % model, TAG)
        log("tool %s" % tool, TAG)
        log("keytool %s" % keytool, TAG)
        key_list = []
        if includeDelete:
            items = Key.objects().all()
        else:
            items = Key.objects(status__ne=KEY_STATUS_DELETED)
        
        for key in items:
            dbprojects = common.string2List(key.project)
            dbmodels = common.string2List(key.model)
            dbtools = common.string2List(key.target_tool)
            dbkeytools = common.string2List(key.target_keytool)
            if (DEBUG): logD("dbprojects %s" % str(dbprojects), TAG)
            if (DEBUG): logD("dbmodels %s" % str(dbmodels), TAG)
            if (DEBUG): logD("dbtools %s" % str(dbtools), TAG)
            if ((dbprojects is None)
                and (dbmodels is None)
                and (dbtools is None)
                and (dbkeytools is None)
                ):
                continue

            found = self.matchKey(project, model, tool, keytool, dbprojects, dbmodels, dbtools, dbkeytools)
            if found:
                key_list.append(KeyInfo(keyDB=key))
        if (DEBUG): logD("key_list %s" % str(key_list), TAG)
        return key_list

    def is_fid_exists(self, fid):
        if (DEBUG): logD("is_fid_exists %s" % fid, TAG)
        items = Key.objects(status__ne=KEY_STATUS_DELETED)
        found = None
        for key in items:
            if key is not None:
                if (DEBUG): logD("key.name %s" % key.name, TAG)
                if key.files is not None and len(key.files) > 0:
                    for file in key.files:
                        if file is not None and file.fid is not None and len(file.fid) > 0:
                            if (DEBUG): logD("file.fid %s" % file.fid, TAG)
                            if fid == file.fid:
                                found = key
                                break
            
            if found is not None:
                break
        
        if (DEBUG): logD("found '%s'" % (found.name if found is not None else ""), TAG)
        return found

    def delete_key(self, key_id):
        log("Delete %s" % key_id, TAG)
        key_info = self.get_key(key_id)
        ret = common.ERR_FAILED
        msg = ""
        if (key_info is not None and key_info.id is not None):
            if (DEBUG): logD("Found one key %s" % key_info.id, TAG)
            if (key_info.keyondb is not None):
                ret = common.ERR_NONE
                for listener in self.listeners:
                    if listener is not None:
                        if (DEBUG): logD("call onKeyDeleted")
                        ret = listener.onKeyDeleted(key_info)
                        if ret != common.ERR_NONE:
                            msg = "%s not allowed to delete by %s" % (key_id, listener.getName())
                            logE(msg, TAG)
                            break
                if ret == common.ERR_NONE:
                    try:
                        # key_info.keyondb.delete()
                        # current_time = datetime.utcnow()
                        # key_info.keyondb.update(status = KEY_STATUS_DELETED, last_update_time=current_time)
                        # key_info.appendHistory("Deleted", updateDB=True)
                        key_info.updateStatus(KEY_STATUS_DELETED, True)

                        if (DEBUG): logD("delete key file")
                        if key_info.fids is not None and len(key_info.fids) > 0:
                            for fname, fid in key_info.fids.items():
                                found = self.is_fid_exists(fid)
                                if found is None :
                                    log("Delete %s with fid %s" % (fname, fid))
                                    storageMgr().delete(fid)
                                else:
                                    log("Not delete fid %s, file is in used by %s" % (fid, found.name))
                        else:
                            log("Not fids to delete", TAG)

                        if (DEBUG): logD("delete pub file")
                        if key_info.pubfids is not None and len(key_info.pubfids) > 0:
                            for fid in key_info.pubfids:
                                found = self.is_fid_exists(fid)
                                if found is None :
                                    log("Delete pub key with fid %s" % (fid))
                                    storageMgr().delete(fid)
                                else:
                                    log("Not delete fid %s, file is in used by %s" % (fid, found.name))
                        else:
                            log("Not pubfids to delete", TAG)
                        ret = common.ERR_NONE
                    except:
                        traceback.print_exc()
                        msg = "Remove %s on db failed"  % key_id
                        logE(msg, TAG)
                        ret = common.ERR_EXCEPTION
                # else: DO NOTHING
            else:
                msg = "Not key on db to delete"
                logE(msg, TAG)
                ret = common.ERR_NOT_FOUND
        else:
            msg = "Not match/found key_id %s" % key_id
            logE(msg, TAG)
            ret = common.ERR_NOT_FOUND
        
        return [ret, key_info if ret == common.ERR_NONE else msg]

    # update key status
    def set_default(self, key_id, set_default):
        if (DEBUG): logD("set_default %s" % set_default, TAG)
        if (DEBUG): logD("Search key key_id %s" % key_id, TAG)
        # TODO: check status/id param

        # search key first
        _key = Key.objects(id=key_id).first()

        if (_key is None):
            logE("Key not found", TAG)
            return common.ERR_NOT_FOUND
        try:
            keyinfo = KeyInfo(keyDB=_key)
            ret = keyinfo.setDefault(set_default, True)
            # _key.update(isdefault = set_default)
        except:
            traceback.print_exc()
            logE("Update key default failed", TAG)
            return common.ERR_FAILED
        
        return common.ERR_NONE

    def onFileDeleted(self, fid):
        if (DEBUG): logD("onFileDeleted fid %s" % (fid), TAG)
        return common.ERR_NONE

    def addPolicy(self, key_id, action, userid = None, remoteIp = None, rsa = None):
        log("addPolicy %s" % key_id, TAG)
        key_info = self.get_key(key_id)
        ret = common.ERR_NONE
        msg = ""
        if (key_info is not None and key_info.id is not None):
            if (DEBUG): logD("Found one key %s" % key_info.id, TAG)
            if (key_info.keyondb is not None):
                if rsa is not None and len(rsa) > 0:
                    ret = enc.ssh_rsa_verify_id_rsa(rsa)
                    if ret != common.ERR_NONE:
                        logE("Invalid input rsa %s" % rsa, TAG)
                        return [common.ERR_INVALID_DATA, "Invalid rsa data"]
                    if (DEBUG): logD("Check if rsa exist", TAG)
                    if (DEBUG): logD(rsa, TAG)
                    exists = False
                    if key_info.policyObj is not None and key_info.policyObj.policy is not None:
                        if action in key_info.policyObj.policy:
                            acclist = key_info.policyObj.policy [action]
                            if acclist is not None and len(acclist) > 0:
                                for acc in acclist:
                                    if acc is not None and acc.rsaFid is not None and len(acc.rsaFid) > 0:
                                        for fidrsa in acc.rsaFid:
                                            if (DEBUG): logD("fidrsa %s" % fidrsa, TAG)
                                            f = tempfile.NamedTemporaryFile()
                                            ret = storageMgr().readFile(fidrsa, f.name)
                                            if ret == common.ERR_NONE:
                                                frsa = common.read_string_from_file(f.name)
                                                if (DEBUG): logD("frsa %s" % frsa, TAG)
                                                if frsa == rsa:
                                                    if (DEBUG): logD("rsa existed")
                                                    exists = True
                                                    break
                                            f.close()
                                    if exists:
                                        break
                    if not exists:
                        if (DEBUG): logD("rsa not existed,make new one")
                        [ret, meta, fid] = storageMgr().writeBuf2File(bytes(rsa, 'utf-8'))
                    else:
                        fid = None
                else:
                    fid = None
                if remoteIp is None or len(remoteIp) == 0:
                    remoteIp = None
                if ret == common.ERR_NONE:
                    ret = key_info.addAcctoPolicy(action, userid, remoteIp, fid, updateDB=True)

                    if ret != common.ERR_NONE:
                        storageMgr().delete(fid)
            else:
                msg = "Not key on db to add policy"
                logE(msg, TAG)
                ret = common.ERR_NOT_FOUND
        else:
            msg = "Not match/found key_id %s" % key_id
            logE(msg, TAG)
            ret = common.ERR_NOT_FOUND
        
        return [ret, msg]

    def delPolicy(self, key_id, action = None, userid = None, remoteIp = None, rsa = None):
        log("delPolicy %s" % key_id, TAG)
        key_info = self.get_key(key_id)
        ret = common.ERR_NONE
        msg = ""
        if (key_info is not None and key_info.id is not None):
            if (DEBUG): logD("Found one key %s" % key_info.id, TAG)
            if (key_info.keyondb is not None):
                if (DEBUG): logD("Check if rsa exist", TAG)
                if (DEBUG): logD(rsa, TAG)
                exists = False
                delFids = []
                if (DEBUG): logD("get fid to be delete", TAG)
                if key_info.policyObj is not None and key_info.policyObj.policy is not None:
                    if action in key_info.policyObj.policy:
                        acclist = key_info.policyObj.policy [action]
                        if acclist is not None and len(acclist) > 0:
                            for acc in acclist:
                                if acc is not None and acc.rsaFid is not None and len(acc.rsaFid) > 0:
                                    for fidrsa in acc.rsaFid:
                                        if (DEBUG): logD("fidrsa %s" % fidrsa, TAG)
                                        delFids.append(fidrsa)
                    
                # TODO: delete specifi rule, not all
                ret = key_info.delPolicy(True)
                
                if ret == common.ERR_NONE:
                    msg = "Delete ok"
                    if (DEBUG): logD("Delete ok, delete file")
                    for fid in delFids:
                        if (DEBUG): logD("delete %d" % fid, TAG)
                        storageMgr().delete(fid)
                else:
                    msg = "delete policy on db failed %d" % ret
                    logE(msg, TAG)
            else:
                msg = "Not key on db to delete"
                logE(msg, TAG)
                ret = common.ERR_NOT_FOUND
        else:
            msg = "Not match/found key_id %s" % key_id
            logE(msg, TAG)
            ret = common.ERR_NOT_FOUND
        
        return [ret, msg]

    # return array with error code and accinfo if success, else error message
    def checkPolicy(self, key_info, action, userid, remoteIp = None):
        if (DEBUG): logD("checkPolicy user %s action %s remoteIp %s" % (action, userid, remoteIp), TAG)
        allow = False
        msg = ""
        if key_info is not None:
            if (DEBUG): logD("key id: %s" % key_info.id, TAG)
            from server.login.user_mng import usrMgr
            userexist = usrMgr().is_userid_exist(userid, ready_status_only=True)
            if userexist == common.ERR_EXISTED:
                if key_info.policyObj is not None:
                    allowacc = key_info.policyObj.isAllow(action, userid, remoteIp)
                    # msg = "allow %d" % allow
                    if allowacc is None:
                        allow = False
                        msg = "Account not allow"
                        logE("Account %s not allow" % userid, TAG)
                    else:
                        allow = True
                        msg = allowacc
                        log("Account %s allow" % userid, TAG)
                        # msg = key_info.policyObj.policy[action]
                else:
                    allow = False
                    msg = "Not policy is set, not allow"
                    log(msg, TAG)
            else:
                allow = False
                msg = "userid %s not exist or not active, ret %d" % (userid, userexist)
                log(msg, TAG)

        else:
            allow = False
            msg = "key_info not found"
            log(msg, TAG)
        return [allow, msg]

    # prepare key to download
    def getDownloadKeys(self, key_id, userid, remoteIp = None, rsa = None):
        if (DEBUG): logD("getDownloadKeys key %s" % key_id, TAG)
        ret = common.ERR_NONE
        msg = None
        outfile = None
        if userid is not None and key_id is not None:
            if (DEBUG): logD("get key %s" % key_id, TAG)
            key_info = self.get_key(key_id)
            if key_info is not None:
                if (DEBUG): logD("get checkPolicy %s" % key_id, TAG)
                # check policy for current user
                [allow, msg] = self.checkPolicy(
                        key_info, 
                        POLICY_ACTION_DOWNLOAD, 
                        userid,
                        remoteIp
                        )
                if not allow:
                    logE("not allow user %s to download key %s, %s" % (userid, key_id, msg), TAG)
                    ret = common.ERR_PROHIBIT
                    msg = "User not allow to download"
                else:
                    acc = msg
                    if rsa is not None and len(rsa) > 0:
                        if (DEBUG): logD("check if RSA is existed %s" % rsa, TAG)
                        exists = False
                        if key_info.policyObj is not None and key_info.policyObj.policy is not None:
                            if POLICY_ACTION_DOWNLOAD in key_info.policyObj.policy:
                                acclist = key_info.policyObj.policy [POLICY_ACTION_DOWNLOAD]
                                if acclist is not None and len(acclist) > 0:
                                    for acc in acclist:
                                        if acc is not None and acc.rsaFid is not None and len(acc.rsaFid) > 0:
                                            for fidrsa in acc.rsaFid:
                                                if (DEBUG): logD("fidrsa %s" % fidrsa, TAG)
                                                f = tempfile.NamedTemporaryFile()
                                                if (DEBUG): logD("f.name %s" % f.name, TAG)
                                                ret = storageMgr().readFile(fidrsa, f.name)
                                                if ret == common.ERR_NONE:
                                                    frsa = common.read_string_from_file(f.name)
                                                    if (DEBUG): logD("frsa %s" % frsa, TAG)
                                                    if frsa == rsa:
                                                        if (DEBUG): logD("rsa existed")
                                                        exists = True
                                                        break
                                                f.close()
                                        if exists:
                                            break
                        if not exists:
                            if (DEBUG): logD("rsa not existed", TAG)
                            ret = common.ERR_NOT_EXISTED
                            msg = "Invalid RSA"
                        # else
                        # Well done, found rsa
                    else:
                        if (DEBUG): logD("get last rsa in db to encrypt", TAG)
                        if acc is not None and acc.rsaFid is not None and len(acc.rsaFid) > 0:
                            count = len(acc.rsaFid) - 1
                            fid = None
                            # get last one
                            while count >= 0:
                                if acc.rsaFid[count] is not None and len(acc.rsaFid[count]) > 0:
                                    fid = acc.rsaFid[count]
                                    break
                                count -= 1
                            if (DEBUG): logD("count %d fid %s" % (count, fid if fid is not None else "not found"), TAG)
                            if count >= 0 and fid is not None and len(fid) > 0:
                                f = tempfile.NamedTemporaryFile()
                                ret = storageMgr().readFile(fid, f.name)
                                if ret == common.ERR_NONE:
                                    frsa = common.read_string_from_file(f.name)
                                    if (DEBUG): logD("frsa %s" % frsa, TAG)
                                    if frsa is not None and len(frsa) > 0:
                                        rsa = frsa
                                        # break
                                f.close()
                            else:
                                if (DEBUG): logD("Not valid RSA", TAG)
                                ret = common.ERR_NOT_EXISTED
                                msg = "Not valid RSA"

                    # read fids from key_info, put to temp dir
                    # zip temp dir, run ssh-gen to encrypt zip file
                    # send zip file to user
                    if ret == common.ERR_NONE and rsa is not None and len(rsa) > 0:
                        if (DEBUG): logD("Get all keys and put to temp dir", TAG)
                        if key_info.fids is not None and len(key_info.fids) > 0:
                            with tempfile.TemporaryDirectory() as tmpdirname:
                                if (DEBUG): logD("tem dir %s" % tmpdirname, TAG)
                                fpathkeydir = os.path.join(tmpdirname, key_id)
                                common.mkdir(fpathkeydir)
                                # private one
                                if (DEBUG): logD("Prepare private key", TAG)
                                for key, fid in key_info.fids.items():
                                    fpath = os.path.join(fpathkeydir, key)
                                    if (DEBUG): logD("temp fid %s fpath %s" % (fid, fpath), TAG)
                                    ret = storageMgr().readFile(fid, fpath)
                                    if ret != common.ERR_NONE:
                                        logE("read fid %s failed" % fid, TAG)
                                        msg = "Read key failed"
                                        break
                                if ret == common.ERR_NONE:
                                    fzip = os.path.join(tmpdirname, key_id + ".zip")
                                    frsa = tempfile.NamedTemporaryFile()

                                    if (DEBUG): logD("zip %s to %s" % (fpathkeydir, fzip), TAG)
                                    ret = common.zipfolder(fpathkeydir, fzip)
                                    common.rmdirs(fpathkeydir)
                                    if ret:
                                        if (DEBUG): logD("write rsa to %s" % (frsa.name), TAG)
                                        ret = common.write_string_to_file(frsa.name, rsa)
                                        
                                        if ret:
                                            
                                            temp_outdir = os.path.join(tmpdirname, key_id)
                                            if (DEBUG): logD("temp_outdir %s" % (temp_outdir), TAG)
                                            
                                            if not os.path.exists(temp_outdir):
                                                common.mkdir(temp_outdir)
                                            
                                            ret = enc.ssh_rsa_encrypt_id_rsa_file(frsa.name, fzip, temp_outdir, key_id)
                                            if os.path.exists(fzip):
                                                os.remove(fzip)

                                            # Copy public files to download folder
                                            if ret == common.ERR_NONE and key_info.pubfids is not None and len(key_info.pubfids) > 0:
                                                # copoy public one to download folder
                                                if (DEBUG): logD("Prepare public key", TAG)
                                                for fid in key_info.pubfids:
                                                    metafile = storageMgr().readMetaFile(fid)
                                                    if metafile is None:
                                                        logE("read meta for fid %s failed" % fid, TAG)
                                                        msg = "Read meta key failed"
                                                        ret = common.ERR_FAILED
                                                        break
                                                    pubdir = os.path.join(temp_outdir, "public")
                                                    if not os.path.exists(pubdir):
                                                        common.mkdir(pubdir)
                                                    fpath = os.path.join(pubdir, metafile.fname)
                                                    if (DEBUG): logD("temp fid %s fpath %s" % (fid, fpath), TAG)
                                                    ret = storageMgr().readFile(fid, fpath)
                                                    if ret != common.ERR_NONE:
                                                        logE("read fid %s failed" % fid, TAG)
                                                        msg = "Read pub key failed"
                                                        break
                                            if ret == common.ERR_NONE:
                                                outfile = os.path.join(KEY_DOWNLOAD_DIR, key_id + ".zip")
                                                if (DEBUG): logD("zip %s to %s" % (temp_outdir, outfile), TAG)
                                                ret = common.zipfolder(temp_outdir, outfile)
                                                if ret:
                                                    ret = common.ERR_NONE
                                                    log("Zip key ok to %s" % outfile)
                                                    msg = outfile
                                                else:
                                                    ret = common.ERR_FAILED
                                                    msg = "post processing file failed"
                                                    logE("zip file failed %s" % outfile, TAG)
                                            else:
                                                ret = common.ERR_FAILED
                                                msg = "encrypt file failed"
                                                logE("encrypt file failed", TAG)
                                        else:
                                            ret = common.ERR_FAILED
                                            msg = "prepare rsa file failed"
                                            logE("prepare rsa file failed", TAG)

                                    else:
                                        if os.path.exists(fzip):
                                            os.remove(path)
                                        ret = common.ERR_FAILED
                                        msg = "prepare file failed"
                                        logE("zip folder key failed", TAG)

                                    frsa.close()
                                    f.close()
                                else:
                                    logE("read key failed", TAG)
                                    ret = common.ERR_NOT_FOUND
                                    msg = "read key failed"
                                    common.rmdirs(fpathkeydir)
                        else:
                            logE("Not key for id %s to download" % key_id, TAG)
                            ret = common.ERR_NOT_FOUND
                            msg = "not key to download"
            else:
                ret = common.ERR_NOT_FOUND
                logE("key %s not found" % key_id, TAG)
                msg = "key not found"

        else:
            ret = common.ERR_INVALID_ARGS
            msg = "invalid userid/keyid"
            logE("invalid userid/keyid", TAG)
        return [ret, msg]
                

    def getPublicDownloadKeys(self, key_id):
        if (DEBUG): logD("getPublicDownloadKeys key %s" % key_id, TAG)
        ret = common.ERR_NONE
        msg = None
        outfile = None
        if (DEBUG): logD("get key %s" % key_id, TAG)
        key_info = self.get_key(key_id)
        if key_info is not None:
            if (DEBUG): logD("Get all public keys and put to temp dir", TAG)
            if key_info.pubfids is not None and len(key_info.pubfids) > 0:
                with tempfile.TemporaryDirectory() as tmpdirname:
                    if (DEBUG): logD("tem dir %s" % tmpdirname, TAG)
                    fpathkeydir = os.path.join(tmpdirname, key_id)
                    common.mkdir(fpathkeydir)
                    for fid in key_info.pubfids:
                        metafile = storageMgr().readMetaFile(fid)
                        if metafile is None:
                            logE("read meta for fid %s failed" % fid, TAG)
                            msg = "Read meta key failed"
                            ret = common.ERR_FAILED
                            break
                        fpath = os.path.join(fpathkeydir, metafile.fname)
                        if (DEBUG): logD("temp fid %s fpath %s" % (fid, fpath), TAG)
                        ret = storageMgr().readFile(fid, fpath)
                        if ret != common.ERR_NONE:
                            logE("read fid %s failed" % fid, TAG)
                            msg = "Read key failed"
                            break
                    if ret == common.ERR_NONE:
                        outfile = os.path.join(KEY_DOWNLOAD_DIR, key_id + ".zip")
                        if (DEBUG): logD("zip %s to %s" % (fpathkeydir, outfile), TAG)
                        ret = common.zipfolder(fpathkeydir, outfile)
                        common.rmdirs(fpathkeydir)
                        if ret:
                            ret = common.ERR_NONE
                            log("Zip key ok to %s" % outfile)
                            msg = outfile
                        else:
                            if os.path.exists(outfile):
                                os.remove(outfile)
                            ret = common.ERR_FAILED
                            msg = "prepare file failed"
                            logE("zip folder key failed", TAG)

                    else:
                        logE("read key failed", TAG)
                        ret = common.ERR_NOT_FOUND
                        msg = "read key failed"
                        common.rmdirs(fpathkeydir)
            else:
                ret = common.ERR_NOT_FOUND
                logE("key %s has no public key" % key_id, TAG)
                msg = "no public key"
        else:
            ret = common.ERR_NOT_FOUND
            logE("key %s not found" % key_id, TAG)
            msg = "key not found"

        return [ret, msg]
                


    def prepareKey(self, key_info, key_dir, fnames=None):
        # Get key basing on key id, or use default one
        log ("prepareKey: %s" % key_dir, TAG, True)
        if fnames is not None:
            log("prepare key with fname: %s" % str(fnames), TAG)
        ret = [common.ERR_FAILED, "Something wrong"]

        # logD("key_info %s" % key_info.toString())
        if (key_info != None):
            try:
                # COPY KEY DATA TO OUTPUT FOLDER.
                # FIXME: SHOULD PROTECT/ENCRYPT IT?
                
                log("Get key", TAG)
                # TODO: Need to make sure that new key is used, not default one
                if (key_info.data_type == database.key.KEY_DATA_TYPE_FILE):
                    if ((key_info.files is not None and len(key_info.files) > 0) or 
                        ((key_info.fids is not None and len(key_info.fids) > 0))):
                        if len(key_info.fids) > 0:
                            no_key = 0
                            for fname, fid in key_info.fids.items():
                                if fnames is None or fname in fnames:
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
                                    no_key += 1
                                else:
                                    if (DEBUG): logD("Skip fname %s" % fname, TAG)
                            
                            if no_key > 0:
                                if (DEBUG): logD("Found %d keys" % no_key, TAG)
                                ret = [common.ERR_NONE, ""] # WELL DONE
                            else:
                                logE("Not found any key", TAG)
                                ret = [common.ERR_NO_DATA, "not found key"]
                            
                        elif len(key_info.files) > 0:
                            for fname, fpath in key_info.files.items():
                                if fnames is None or fname in fnames:
                                    if (DEBUG): logD("Copy %s from %s to %s" % (fname, fpath, key_dir))
                                    from server.key.key_mng import keyMgr
                                    shutil.copy(keyMgr().get_full_key_path(fpath), key_dir)
                                    no_key += 1
                                else:
                                    if (DEBUG): logD("Skip fname %s" % fname, TAG)
                            
                            if no_key > 0:
                                if (DEBUG): logD("Found %d keys" % no_key, TAG)
                                ret = [common.ERR_NONE, ""] # WELL DONE
                            else:
                                logE("Not found any key", TAG)
                                ret = [common.ERR_NO_DATA, "not found key"]
                            
                        else:
                            ret = [common.ERR_NO_DATA, "no key to sign"]
                    else:
                        ret = [common.ERR_INVALID_DATA, "Invalid key data"]
                else:
                    ret = [common.ERR_INVALID_DATA, "Not suitable key"]

                # prepare public key id
                log("Get public key", TAG)
                if key_info.pubfids is not None and len(key_info.pubfids) > 0:
                    for fid in key_info.pubfids:
                        metafile = storageMgr().readMetaFile(fid)
                        if metafile is None:
                            logE("read meta for public fid %s failed" % fid, TAG)
                            ret = common.ERR_FAILED
                            break
                        fpath = os.path.join(key_dir, metafile.fname)
                        if (DEBUG): logD("temp fid %s fpath %s" % (fid, fpath), TAG)
                        ret = storageMgr().readFile(fid, fpath)
                        if ret != common.ERR_NONE:
                            logE("read pub fid %s failed" % fid, TAG)
                            break
            except:
                traceback.print_exc()
                ret = [common.ERR_EXISTED, "Exception occur"]
        else:
            ret = [common.ERR_INVALID_DATA, "Invalid key id"]
        return ret

# key: tool name, value: list, 1st is tool object, 2nd is descryption
g_GenKeyTools = {}

# key: tool name, value: list, 1st is tool object, 2nd is descryption
g_ImportKeyTools = {}

def add_key_tool(keytool, desc, visible = False):
    if keytool is not None:
        name = keytool.getName()
        if (DEBUG): logD("add_key_tool %s" % name, TAG)
        if name not in g_GenKeyTools:
            g_GenKeyTools[name] = [keytool, desc, visible]

        else:
            raise ValueError("add_key_tool: Key %s already exist" % name)
    else:
        raise ValueError("add_key_tool: Invalid key tool")

def add_import_key_tool(keytool, desc):
    if keytool is not None:
        name = keytool.getName()
        if (DEBUG): logD("add_import_key_tool %s" % name, TAG)
        if name not in g_ImportKeyTools:
            g_ImportKeyTools[name] = [keytool, desc]
        else:
            raise ValueError("add_import_key_tool: Key %s already exist" % name)
    else:
        raise ValueError("add_import_key_tool: Invalid key tool")

def get_keytool_from_name(name):
    if (DEBUG): logD("get_keytool_from_name %s" % name, TAG)
    if (len(name) > 0 and name in g_GenKeyTools):
        return g_GenKeyTools[name][0]
    else:
        return None

def get_import_key_tool(name):
    if (DEBUG): logD("get_import_key_tool %s" % name, TAG)
    if (len(name) > 0 and name in g_ImportKeyTools):
        if (DEBUG): logD("Found", TAG)
        return g_ImportKeyTools[name][0]
    else:
        if (DEBUG): logD("Not Found", TAG)
        return None

def get_keytool_list():
    return g_GenKeyTools

def get_visible_keytool_list():
    list = {}
    for item, val in g_GenKeyTools.items():
        if val[2]:
            list[item] = val
    return list

def get_import_keytool_list():
    return g_ImportKeyTools

g_keymgr = None

def keyMgr():
    global g_keymgr
    if g_keymgr is None:
        g_keymgr = KeyMgr()

    return g_keymgr

# init key management system
def init_key_management(app = None):
    log("init_key_management", TAG, toFile=True)
    if not os.path.exists(KEY_DIRECTORY):
        os.makedirs(KEY_DIRECTORY)
    
    
    if not os.path.exists(KEY_DOWNLOAD_DIR):
        os.makedirs(KEY_DOWNLOAD_DIR)

    global g_keymgr
    g_keymgr = KeyMgr()

    ret = common.ERR_NONE
    try:
        # Renesas
        from server.key.renesas.root_key_tool import RenesasRootKeyTool
        add_key_tool(RenesasRootKeyTool(), "Renesas - Root key")
        
        from server.key.renesas.sb_key_tool import RenesasSecureBootKeyTool
        add_key_tool(RenesasSecureBootKeyTool(), "Renesas - Secure boot key")

        
        from server.key.renesas.key_cert_tool import RenesasKeyCertTool
        add_key_tool(RenesasKeyCertTool(), "Renesas - Key certificate", True)

        from server.key.renesas.pri_dbg_cert_tool import RenesasPriDbgCertTool
        add_key_tool(RenesasPriDbgCertTool(), "Renesas - Primary Debug Certificate", True)


        # quectel
        from server.key.quectel.root_key_tool import QuectelSbRootKeyTool
        add_key_tool(QuectelSbRootKeyTool(), "Quectel - Root secure boot key")

        from server.key.quectel.sb_attest_key_tool import QuectelSbAttestKeyTool
        add_key_tool(QuectelSbAttestKeyTool(), "Quectel - Secure boot Attestion key")

        from server.key.quectel.sb_dm_key_tool import QuectelSbDMKeyTool
        add_key_tool(QuectelSbDMKeyTool(), "Quectel - Secure boot DM verity key")

        # android
        from server.key.android.app_key_tool import AndroidAppKeyTool
        add_key_tool(AndroidAppKeyTool(), "Android - App/Apk key")
        
        from server.key.android.avb_key_tool import AndroidAvbKeyTool
        add_key_tool(AndroidAvbKeyTool(), "Android - AVB key")

        from server.key.android.ota_key_tool import AndroidOtaKeyTool
        add_key_tool(AndroidOtaKeyTool(), "Android - Platform OTA key")

        from server.key.android.platform_key_tool import AndroidPlatformKeyTool
        add_key_tool(AndroidPlatformKeyTool(), "Android - Platform key")


        # fota
        from server.key.vinfast.fota_enc_key_tool import VinFotaEncryptKeyTool
        add_key_tool(VinFotaEncryptKeyTool(), "VinFast - Fota Encryption key")

        from server.key.vinfast.fota_sign_key_tool import VinFotaSignKeyTool
        add_key_tool(VinFotaSignKeyTool(), "VinFast - Fota Signature key")

        # common key gen
        from server.key.general.gen_key_tool import GenKeyTool
        add_key_tool(GenKeyTool(), "Generate Key tool", True)

        # import key
        from server.key.import_key import ImportKeyTool
        add_import_key_tool(ImportKeyTool(), "Import key")

        # oem key gen
        from server.key.vinfast.oem_key_tool import VinOemKeyTool
        add_key_tool(VinOemKeyTool(), "VinFast - OEM key")

        # vinfast key gen
        from server.key.vinfast.vf_key_tool import VinFastKeyTool
        add_key_tool(VinFastKeyTool(), "VinFast - Key")

        # cep key tool
        from server.key.cep.cep_key_tool import CepKeyTool
        add_key_tool(CepKeyTool(), "TBOX CEP - Key", True)

    except:
        traceback.print_exc()
        logE("Regiseter key tool failed", TAG)
        ret = common.ERR_EXCEPTION

    return ret


