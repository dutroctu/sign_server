#!/usr/bin/env python
#
#  KEY INFO
#


from flask import Flask
from flask_restful import Api, Resource, reqparse
from flask import send_file
from flask import render_template
from flask import request, abort, jsonify, send_from_directory
from server.app import app

from server.app import KEEP_OUTPUT_FILE
from server.app import DEBUG
from server.app import DEBUG_DB
import os
from server.applog import log
from server.applog import logE
from server.applog import logD
from server import common as common
import traceback
import shutil
from server.database.key import Key
from server.database.key import KeyFile
from server.database.key import KEY_STATUS_NOT_READY
from server.database.key import KEY_STATUS_READY
from server.database.key import KEY_STATUS_DELETED
from server.database.key import KEY_SOURCE_IMPORT_API
from server.database.key import KEY_DATA_TYPE_RAW
from server.database.key import KEY_DATA_TYPE_FILE
from server.database.db_mgr import dbMgr
from server.storage import storageMgr
import json
from datetime import datetime

# max len of history field
MAX_HISTORY_LENGTH = 1024
CUT_HISTORY_LENGTH = MAX_HISTORY_LENGTH/2


TAG="KeyInfo"

#
# Information of account to be used by key policy, in format:
# {
# userid:
# remoteIp:['10.xxx','xxx']
# rsaFid:['xyz', 'def']
# }
#
class AccountPolicy:
    # user id. Not using username, to avoid username is power, and deleted, then re-create, its policy should be clear.
    userid = None 

    # remote ip list
    remoteIp = []

    # ssh id-rsa fid.
    # this is fid of storagemgr, not real file.
    rsaFid = []

    def __init__(self):
        self.userid = None
        self.remoteIp = []
        self.rsaFid = [] # array of fid
    
    def toString(self):
        ret = ""
        ret += "userid: %s;\n" % self.userid
        ret += "remoteIp: %s;\n" % str(self.remoteIp)
        ret += "rsaFid: %s;\n" % str(self.rsaFid)

        return ret

    # add remote ip
    def addRemoteIp(self, ip):
        if (DEBUG): logD("addRemoteIp %s" % ip, TAG)
        if ip is not None and len(ip) > 0:
            if ip not in self.remoteIp: # not exist, add new
                self.remoteIp.append(ip)
            return common.ERR_NONE
        else:
            logE("addRemoteIp failed, invali arg", TAG)
            return common.ERR_INVALID_ARGS

    # add fid for ssh id-rsa
    def addRsafid(self, fid):
        if (DEBUG): logD("addRsafid %s" % fid, TAG)
        if fid is not None and len(fid) > 0:
            if fid not in self.rsaFid:
                self.rsaFid.append(fid)
            return common.ERR_NONE
        else:
            logE("addRsafid failed, invali arg", TAG)
            return common.ERR_INVALID_ARGS

    # update account info
    def updateAcc(self, acc):
        if (DEBUG): logD("updateAcc %s" % acc.toString(), TAG)
        if acc is None:
            return common.ERR_INVALID_ARGS
        
        if acc.remoteIp is not None and len(acc.remoteIp) > 0:
            for ip in acc.remoteIp:
                if ip not in self.remoteIp: # check if not exist, add
                    if (DEBUG): logD("Add ip %s " % ip, TAG)
                    self.remoteIp.append(ip)

        
        if acc.rsaFid is not None and len(acc.rsaFid) > 0:
            for rsa in acc.rsaFid:
                if rsa not in self.rsaFid: # check if not exist, add
                    if (DEBUG): logD("Add rsaFid %s " % rsa, TAG)
                    self.rsaFid.append(rsa)

        return common.ERR_NONE
    
    # check if account is match policy
    def matchAcc(self, acc):
        if (DEBUG): logD("matchAcc %s" % acc.toString(), TAG)
        if (DEBUG): logD("myAcc %s" % self.toString(), TAG)

        if self.userid != acc.userid: # different use, quit
            return False
        
        foundIP = False
        foundRsa = False
        # check remote ip
        # rule: remote ip must be set, if not, quit
        if self.remoteIp is not None and len(self.remoteIp) > 0:
            if acc.remoteIp is not None and len(acc.remoteIp) > 0:
                for ip in self.remoteIp:
                    for ip2 in acc.remoteIp:
                        if ip == ip2:
                            foundIP = True
                            break
                    if foundIP:
                        break
            else:
                foundIP = False
        else: # policy require ip must be included
            log("No remote ip set for %s " % str(self.userid), TAG)
            foundIP = False

        
        # check ssh id rsa
        # rule: ssh id rsa must be set, if not, quit
        if foundIP:
            if self.rsaFid is not None and len(self.rsaFid) > 0:
                if acc.rsaFid is not None and len(acc.rsaFid) > 0:
                    for ip in self.rsaFid:
                        for ip2 in acc.rsaFid:
                            if ip == ip2:
                                foundRsa = True
                                break
                        if foundRsa:
                            break
                else:
                    foundRsa = True # not a bug... there is no info about rsa when requeset download...
            else:
                foundRsa = False # policy require RSA must be included
                log("No rsa set for %s " % str(self.userid), TAG)

        if (DEBUG): logD("foundIP %d foundRsa %d" % (foundIP, foundRsa), TAG)
        return foundIP and foundRsa

    # convert to json
    def toJson(self):
        if (DEBUG): logD("AccountPolicy toJson", TAG)
        try:
            jdata = {
                "userid":str(self.userid) if self.userid is not None  else "",
                "remoteIp":self.remoteIp if self.remoteIp is not None and len(self.remoteIp) > 0 else [],
                "rsaFid":self.rsaFid if self.rsaFid is not None and len(self.rsaFid) > 0 else [],
                }
            jstring = json.dumps(jdata)
            return jstring
        except:
            traceback.print_exc()
            logE("Convert to json failed", TAG)
            return None

    # get data from json
    def fromJson(self, val):
        if (DEBUG): logD("AccountPolicy fromJson %s" % val, TAG)
        try:
            from bson.objectid import ObjectId
            jdata = json.loads(val)
            self.userid = ObjectId(jdata["userid"]) if "userid" in jdata else None
            self.remoteIp = jdata["remoteIp"] if "remoteIp" in jdata else []
            self.rsaFid = jdata["rsaFid"] if "rsaFid" in jdata else []

            return common.ERR_NONE
        except:
            traceback.print_exc()
            logE("Parse from json failed %s " % val, TAG)
            return common.ERR_EXCEPTION

#
# Policy of each key, in format:
# "<action>":[
#  <AccountPolicy1 (json)>,
#  <AccountPolicy2 (json)>,
# ]
#
class KeyPolicy:
    policy = {}  # key is action, value is list of allow accounts

    def __init__(self):
        self.policy = {}

    def toJson(self):
        if (DEBUG): logD("KeyPolicy toJson", TAG)
        try:
            policyStr = {}
            # convert account policy to json
            for key, value in self.policy.items(): # key is action
                allowAccStr = [] # list of account in json format
                if value is not None and len(value) > 0:
                    for account in value:
                        if account is not None:
                            data = account.toJson()
                            if data is not None:
                                allowAccStr.append(data)
                            else:
                                raise ValueError("Conver json of account policy failed")
                
                policyStr[key] = allowAccStr

            jstring = json.dumps(policyStr)
            return jstring
        except:
            traceback.print_exc()
            logE("Convert to json failed", TAG)
            return None

    # add account to pollicy
    def addAccount(self, action, acc):
        if (DEBUG): logD("addAccount action %s acc %s" % (action, acc), TAG)
        if action in self.policy: # action will follow key_mgr, not check here
            acc2check = self.getAcc(action, acc.userid)
            if acc2check is None:
                if (DEBUG): logD("add new", TAG)
                self.policy[action].append(acc)
            else:
                if (DEBUG): logD("updaet current one", TAG)
                acc2check.updateAcc(acc)
        else:
            if (DEBUG): logD("add new to list", TAG)
            self.policy[action] = [acc]
        return common.ERR_NONE

    # to json
    def fromJson(self, val):
        if (DEBUG): logD("KeyPolicy fromJson %s" % val, TAG)
        try:
            jdata = json.loads(val)
            for action, accstrlist in jdata.items():
                if accstrlist is not None and len(accstrlist) > 0:
                    for accstr in accstrlist:
                        if accstr is not None and len(accstr) > 0:
                            acc = AccountPolicy()
                            acc.fromJson(accstr)
                            self.addAccount(action, acc)
            return common.ERR_NONE
        except:
            traceback.print_exc()
            logE("Parse from json failed %s " % val, TAG)
            return common.ERR_EXCEPTION

    # isAllow, return None if not allow else account policy info
    def isAllow(self, action, userid=None, remoteIp=None, rsa=None):

        if (DEBUG): logD("isAllow action %s userid %s remoteIp %s rsa %s" % (action, userid, remoteIp, rsa), TAG)

        accList = self.policy[action] if action in self.policy else None
        allow = None
        if accList is not None and len(accList) > 0:
            log("action %s support, check account" % action, TAG)
            acc = AccountPolicy()
            acc.userid = userid
            if remoteIp is not None:
                acc.addRemoteIp(remoteIp)
            
            if rsa is not None:
                acc.addRsafid(rsa)
                
            for accitem in accList:
                if accitem.matchAcc(acc):
                    allow = accitem
                    break
        else:
            log("action %s is not allowed" % action, TAG)
            allow = None
        return allow

    # get account policy of a user
    def getAcc(self, action, userid):
        if (DEBUG): logD("getAcc action %s userid %s " % (action, userid), TAG)
        accList = self.policy[action] if action in self.policy else None
        if accList is not None and len(accList) > 0:
            for accitem in accList:
                if accitem.userid == userid:
                    if (DEBUG): logD("Found acc for uid %s" % userid, TAG)
                    return accitem
        
        if (DEBUG): logD("not found acc for uid %s" % userid, TAG)
        return None


# KEY must be uniqued with name + project + model, when it's in active state
# not check if key is deactive, but MUST check again if it's active again
# TODO: be care full the case of dup key when it's activate again

class KeyInfo:

    id = None # KEY ID, generated by database
    name = "" # key name, unique with project and model
    tag = "" # Tag of key, informative only
    alg = "" # alg of key, informative
    pwd = "" # password of key if any
    hint = "" # hint of key, informative
    project = "" # project, like tbox
    model = "" # model, like vf32
    data = "" # raw key data, if file is not specified
    data_type = KEY_DATA_TYPE_RAW # data type, raw or file
    key_source = KEY_SOURCE_IMPORT_API # import from api, web, or generated
    files = {} # list of files of key
    created_time = "" # created time
    last_update_time = "" # last updated time
    status = KEY_STATUS_NOT_READY # status of key
    keyondb = None # keyobject on db

    fids = {} # list of files of key
    encrypted = False
    history = ""
    # default for model-project-market-module
    isdefault = False
    # target tool to use this key
    target_tool = ""# list of sign tool, in string format
    target_keytool = "" # list of keytool, in string format
    signature = "" # signature of critical field, to check if field is modified uncorrectly
    metadata = "" # meta/additional info for this key
    policy = "" # policy string, in json format
    policyObj = None # policy object, match with policy

    rootKeyId = None
    pubfids = []
    title = ""
    def __init__(self,  name=None, 
                        tag=None, 
                        alg=None, 
                        pwd=None, 
                        hint=None, 
                        data = None, 
                        data_type = KEY_DATA_TYPE_RAW, 
                        source_type = KEY_SOURCE_IMPORT_API,
                        keyDB = None
                        ):
        self.id = None
        self.name = ""
        self.tag = ""
        self.alg = ""
        self.pwd = ""
        self.hint = ""
        self.data = ""
        self.data_type = KEY_DATA_TYPE_RAW
        self.key_source = KEY_SOURCE_IMPORT_API
        self.keyondb = None
        self.fids = {}
        self.files = {}
        self.status = KEY_STATUS_NOT_READY
        self.last_update_time = ""
        self.created_time = ""
        self.model = ""
        self.project = ""
        self.encrypted = False
        self.history = ""
        self.isdefault = False
        self.target_tool = ""
        self.target_keytool = ""
        self.policy = ""
        self.metadata = ""
        self.signature = ""
        self.policyObj = None
        self.rootKeyId = None
        self.pubfids = []
        self.title = ""

        if (keyDB is None):
            self.name = name
            self.tag = tag
            self.alg = alg
            self.pwd = pwd
            self.hint = hint
            self.data = data
            self.data_type = data_type
            self.key_source = source_type
        else:
            self.fromKeyDB(keyDB)

    # add file to key
    # auto change to type file after call this api
    def addFile(self, name, path):
        # TODO: should support both raw and file?
        if (DEBUG): logD("addFile name %s, path %s" % (name, path), TAG)
        self.data_type = KEY_DATA_TYPE_FILE 
        self.files[name] = path
    
    # add fid of key
    def addFid(self, name, fid, isPub=False):
        # TODO: should support both raw and file?
        if (DEBUG): logD("addFid name %s, fid %s, isPub=%d" % (name, fid, isPub), TAG)
        self.data_type = KEY_DATA_TYPE_FILE 
        self.fids[name] = fid

        if isPub:
            self.pubfids.append(fid)

    def toString(self):
        ret = ""
        ret += "name: %s;\n" % (self.name if self.name is not None else "None")
        ret += "title: %s;\n" % (self.title if self.title is not None else "None")
        ret += "id: %s;\n" % (self.id if self.id is not None else "None")
        ret += "project: %s;\n" % (self.project if self.project is not None else "None")
        ret += "model: %s;\n" % (self.model if self.model is not None else "None")
        ret += "target_tool: %s;\n" % (self.target_tool if self.target_tool is not None else "None")
        ret += "target_keytool: %s;\n" % (self.target_keytool if self.target_keytool is not None else "None")
        ret += "isdefault: %s;\n" % self.isdefault
        ret += "pubfids: %s;\n" % self.pubfids
        # TODO: More info?
        return ret

    def toJson(self):
        if (DEBUG): logD("KeyInfo toJson", TAG)
        try:
            jsonobj = {}
            jsonobj["id"] = str(self.id)
            jsonobj["name"] = self.name
            jsonobj["title"] = self.title
            jsonobj["project"] = json.dumps(self.project)
            jsonobj["model"] = json.dumps(self.model)
            jstring = json.dumps(jsonobj)
            return jstring
        except:
            traceback.print_exc()
            logE("Convert to keyinfo json failed", TAG)
            return None
            
    # calculate signature
    # not all field will be calculated, just some critical field only.
    def calcSignature(self, key=None):
        if (DEBUG): logD("calcSignature %s" % self.toString(), TAG)
        import hashlib
        signature = None
        try:
            from server.database.db_mgr import dbMgr
            sha256 = hashlib.sha256()
            name = self.name if key is None else key.name
            if name is not None:
                sha256.update(bytes(name, 'utf-8'))
            
            pwd = self.pwd if key is None else key.pwd
            if pwd is not None:
                sha256.update(bytes(pwd, 'utf-8'))
            
            prj = self.project if key is None else key.project
            if prj is not None:
                sha256.update(bytes(prj, 'utf-8'))
            
            model = self.model if key is None else key.model
            if model is not None:
                sha256.update(bytes(model, 'utf-8'))

            tool = self.target_tool if key is None else key.target_tool
            if tool is not None:
                sha256.update(bytes(tool, 'utf-8'))

            keytool = self.target_keytool if key is None else key.target_keytool            
            if keytool is not None:
                sha256.update(bytes(keytool, 'utf-8'))

            policy = self.policy if key is None else key.policy
            if policy is not None:
                sha256.update(bytes(policy, 'utf-8'))
            
            metadata = self.metadata if key is None else key.metadata
            if metadata is not None:
                sha256.update(bytes(metadata, 'utf-8'))
            
            sha256.update(bytes("%d" % self.status if key is None else key.status, 'utf-8'))
            sha256.update(bytes("%d" % self.encrypted if key is None else key.encrypted, 'utf-8'))
            sha256.update(bytes("%d" % self.isdefault if key is None else key.isdefault, 'utf-8'))

            pubfids = self.pubfids if key is None else key.pubfids
            if pubfids is not None and len(pubfids) > 0:
                for fid in pubfids:
                    if fid is not None and len(fid) > 0:
                        sha256.update(bytes(fid, 'utf-8'))

            hashit = dbMgr().hashWithKey(sha256.digest())
            signature = hashit.hex()

            if (DEBUG): logD("calc signature of key: %s" % signature, TAG)
        except :
            traceback.print_exc()
            logE("calcSignature failed")
            return None
        
        if (DEBUG): logD("signature %s" % signature, TAG)
        return signature

    # re-update siguature
    def updateSignature(self, signature=None):
        from server.database.db_mgr import dbMgr
        sign = signature if signature is not None else self.calcSignature()
        if sign is not None:
            self.key.update(signature=sign)
            return common.ERR_NONE
        else:
            logE("update sign failed, invalid data")
            return common.ERR_INVALID_ARGS

    # update key status
    def updateStatus(self, status, updateDB=False):
        if (DEBUG): logD("updateStatus %d updateDB %d" % (status, updateDB), TAG)
        from server.database.db_mgr import dbMgr
        from server.database.key import KEY_STATUS_CNAME
        if status in KEY_STATUS_CNAME:
            old = self.status
            self.status = status
            self.signature = self.calcSignature() # recalc signature
            try:
                if updateDB:
                    if self.keyondb is not None:
                        current_time = datetime.utcnow()

                        self.appendHistory("Update keyondb status from %d to %d" %(old, self.status), updateDB=False)
                        enc_history = dbMgr().encryptDataString2Base64(self.history)
                        if enc_history is not None and self.signature is not None:
                            if (DEBUG): logD("update status", TAG)
                            self.keyondb.update(status = self.status, history=enc_history, signature=self.signature, last_update_time=current_time)
                        else:
                            logE("failed to encrypt history")
                            return common.ERR_FAILED
                    else:
                        logE("update history failed, not db object")
                        return common.ERR_NO_DATA
                #else: not update db
            except :
                traceback.print_exc()
                logE("update db failed")
                return commonn.ERR_EXCEPTION
            return common.ERR_NONE # well done
        else:
            logE("update status failed, invalid data %d" % status)
            return common.ERR_INVALID_ARGS

    # set key as default one
    def setDefault(self, set_default, updateDB=False):
        if (DEBUG): logD("setDefault %d updateDB %d" % (set_default, updateDB), TAG)
        from server.database.db_mgr import dbMgr
        old = self.isdefault
        self.isdefault = set_default
        self.signature = self.calcSignature()
        try:
            if updateDB:
                if self.keyondb is not None:
                    current_time = datetime.utcnow()
                    self.appendHistory("Update keyondb default from %d to %d" %(old, self.status), updateDB=False)
                    
                    enc_history = dbMgr().encryptDataString2Base64(self.history)
                    if enc_history is not None and self.signature is not None:
                        if (DEBUG): logD("update default", TAG)
                        self.keyondb.update(isdefault = set_default, history=enc_history, signature=self.signature, last_update_time=current_time)
                    else:
                        logE("failed to encrypt history")
                        return common.ERR_FAILED
                else:
                    logE("update default failed, not db object")
                    return common.ERR_NO_DATA
            # else: not update db
        except :
            traceback.print_exc()
            logE("update db failed")
            return commonn.ERR_EXCEPTION
        
        return common.ERR_NONE

    # append history for key
    def appendHistory(self, history, updateDB=False):
        from server.database.db_mgr import dbMgr
        if history is not None and len(history) > 0:
            self.history = "%s;\n%s: %s" %(self.history, common.current_time(common.TIME_FORMAT_TO_DISPLAY_SHORT), history)
            hislen = len(self.history)
            if (DEBUG): logD("hislen %d" % hislen, TAG)
            # too much info, clean up history
            if hislen > MAX_HISTORY_LENGTH:
                start = hislen - MAX_HISTORY_LENGTH
                history = self.history[start:hislen]
                self.history = history
                if (DEBUG): logD("self.history %s" % self.history, TAG)
            if updateDB:
                if self.keyondb is not None:
                    enc_history = dbMgr().encryptDataString2Base64(self.history)
                    if enc_history is not None:
                        self.keyondb.update(history=enc_history)
                    else:
                        logE("failed to encrypt history")
                        return common.ERR_FAILED
                else:
                    logE("update history failed, not db object")
                    return common.ERR_NO_DATA
            
            return common.ERR_NONE
        else:
            logE("update history failed, invalid data")
            return common.ERR_INVALID_ARGS

    def getProjects(self):
        return common.string2List(self.project)
    def getModels(self):
        return common.string2List(self.model)
    def getTools(self):
        return common.string2List(self.target_tool)
    def getKeyTools(self):
        return common.string2List(self.target_keytool)
    
    def getPolicy(self):
        # convert to policy object if not convert yet
        if self.policyObj is None and self.policy is not None and len(self.policy) > 0:
            policy = KeyPolicy()
            policy.fromJson(self.policy)
            self.policyObj = policy
        
        return self.policyObj

    # TODO: delete informtion on policy only, not whole policy

    # delete all policy
    def delPolicy(self, updateDB=True):
        if (DEBUG): logD("delPolicy", TAG)
        self.policy = ""
        self.policyObj = None
        self.signature = self.calcSignature()
        if updateDB:
            if self.keyondb is not None:
                current_time = datetime.utcnow()
                self.appendHistory("Delete policy", updateDB=False)
                enc_history = dbMgr().encryptDataString2Base64(self.history)
                if enc_history is not None and self.signature is not None:
                    if (DEBUG): logD("Delete policy", TAG)
                    self.keyondb.update(policy = self.policy, history=enc_history, signature=self.signature, last_update_time=current_time)
                else:
                    logE("failed to encrypt history")
                    return common.ERR_FAILED
            else:
                logE("delete policy failed, not db object")
                return common.ERR_NO_DATA
        return common.ERR_NONE
    
    # delete acc info in specific policy
    def delAccInPolicy(self, action, userid=None, remoteIp=None, rsa=None, updateDB=True):
        # TODO: implement delete acc infor in policy
        pass

    # add policy for key
    def addAcctoPolicy(self, action, userid=None, remoteIp=None, rsa=None, updateDB=True):
        if (DEBUG): logD("addAcctoPolicy action %s, userid %s, ip %s, rsa %s" % (action, userid, remoteIp, rsa), TAG)
        policy = self.getPolicy()
        if policy is None: # not exist policy yet, add new one
            if (DEBUG): logD("create new policy", TAG)
            policy = KeyPolicy()
        
        # build account policy
        acc = AccountPolicy()
        acc.userid = userid
        if remoteIp is not None:
            acc.addRemoteIp(remoteIp)
            
        if rsa is not None:
            acc.addRsafid(rsa)
        # add account to policy
        ret = policy.addAccount(action, acc)

        if ret == common.ERR_NONE:
            self.policy = policy.toJson()
            if self.policy is not None:
                self.policyObj = policy
                self.signature = self.calcSignature()
                # update db
                if updateDB:
                    if self.keyondb is not None:
                        current_time = datetime.utcnow()
                        self.appendHistory("Update policy for %s with usrid %s" %(action, str(userid)), updateDB=False)
                        enc_history = dbMgr().encryptDataString2Base64(self.history)
                        if (DEBUG): logD("update policy", TAG)
                        enc_policy = dbMgr().encryptDataString2Base64(self.policy) if self.policy is not None and len(self.policy) > 0 else ""
                        if enc_history is not None and enc_policy is not None and self.signature is not None:
                            self.keyondb.update(policy = enc_policy, history=enc_history, signature=self.signature, last_update_time=current_time)
                        else:
                            logE("failed to encrypt history")
                            return common.ERR_FAILED
                    else:
                        logE("update policy failed, not db object")
                        return common.ERR_NO_DATA
            else:
                if (DEBUG): logD("Convert json failed", TAG)
                return common.ERR_FAILED
        #else: something wrong
        return ret

    def getMeta(self):
        jdata = {
            "id":str(self.id),
            "name":self.name,
            }
        try:
            jstring = json.dumps(jdata)
            return jstring
        except:
            traceback.print_exc()
            logE("Get meta, Convert to json failed", TAG)
            return None

    def findFids(self, fid):
        if (DEBUG): logD("findFids %s" % fid, TAG)
        found = False
        if fids is not None and len(fids) > 0:
            for key in fids:
                if (DEBUG): logD("key %s" % key, TAG)
                if key == fid:
                    found = True
                    break
        if (DEBUG): logD("found %d" % found, TAG)
        return found

    # Validate key information, True if OK, False if not OK
    def validate(self, incsignature = False):
        if (DEBUG): logD("validate key info, incsignature %d" % incsignature)
        if (self.name is None or len(self.name) == 0): # name must be included
            if (DEBUG): logD("Invalid name")
            return False

        if (self.getProjects() is None): # project must be included
            if (DEBUG): logD("project name")
            return False
        

        if (self.getModels() is None): # model must be included
            if (DEBUG): logD("model")
            return False

        if (self.getTools() is None): # model must be included
            if (DEBUG): logD("tôl")
            return False
        
        # validate signature
        if incsignature:
            calcSign = self.calcSignature()
            if self.signature is not None and self.signature != calcSign:
                logE("mistmatch signature, expected %s calc %s" % (self.signature, calcSign), TAG)
                return False

        # TODO: check more, like key data, etc.
        return True

    def cleanup(self, forceCleanup=False):
        log("cleanup %s" % self.name, TAG)
        for fname, path in self.files.items():
            #TODO; move somewhere if force cleanup is False?
            if path is not None and os.path.exists(path):
                if (DEBUG): logD("Remove fname %s, path %s" % (fname, path), TAG)
                os.remove(path)


        for fname, fid in self.fids.items():
            #TODO; move somewhere if force cleanup is False?
            if (DEBUG): logD("Remove fname %s, fid %s" % (fname, fid), TAG)
            storageMgr().delete(fid, forceCleanup)

    def fromKeyDB(self, key):
        from server.database.db_mgr import dbMgr
        if (DEBUG): logD("fromKeyDB")
        try:
            self.id = key.id
            
            self.name = dbMgr().decryptDataFromBase64(key.name) if key.name is not None and len(key.name) > 0 else ""
            self.tag = dbMgr().decryptDataFromBase64(key.tag) if key.tag is not None and len(key.tag) > 0 else ""
            self.alg = dbMgr().decryptDataFromBase64(key.alg) if key.alg is not None and len(key.alg) > 0 else ""
            self.hint = dbMgr().decryptDataFromBase64(key.hint) if key.hint is not None and len(key.hint) > 0 else ""
            self.data = dbMgr().decryptDataFromBase64(key.data) if key.data is not None and len(key.data) > 0 else ""
            self.history = dbMgr().decryptDataFromBase64(key.history) if key.history is not None and len(key.history) > 0 else ""
            self.pwd = dbMgr().decryptDataFromBase64(key.pwd) if key.pwd is not None and len(key.pwd) > 0 else ""
            self.metadata = dbMgr().decryptDataFromBase64(key.metadata) if key.metadata is not None and len(key.metadata) > 0 else ""
            self.policy = dbMgr().decryptDataFromBase64(key.policy) if key.policy is not None and len(key.policy) > 0 else ""
            self.title = dbMgr().decryptDataFromBase64(key.title) if key.title is not None and len(key.title) > 0 else ""
            
            if self.policy is not None and len(self.policy) > 0:
                policy = KeyPolicy()
                policy.fromJson(self.policy)
                self.policyObj = policy

            self.encrypted = key.encrypted
            self.data_type = key.data_type
            self.key_source = key.key_source
            self.created_time = key.created_time
            self.last_update_time = key.last_update_time
            self.status = key.status
            self.project = key.project
            self.model = key.model
            self.target_tool = key.target_tool if key.target_tool is not None else ""
            self.target_keytool = key.target_keytool if key.target_keytool is not None else ""
            self.isdefault = key.isdefault if key.isdefault is not None else False
            self.keyondb = key
            self.signature = key.signature
            self.rootKeyId = key.rootKeyId
            self.pubfids = key.pubfids if key.pubfids is not None else None
            if (key.files is not None):
                for keyfile in key.files:
                    if (keyfile is not None):
                        if (keyfile.name is not None and len(keyfile.name) > 0):
                            fname = dbMgr().decryptDataFromBase64(keyfile.name)
                            if (keyfile.path is not None and len(keyfile.path) > 0):
                                self.files[fname] = dbMgr().decryptDataFromBase64(keyfile.path)
                            if (keyfile.fid is not None and len(keyfile.fid) > 0):
                                self.fids[fname] = dbMgr().decryptDataFromBase64(keyfile.fid)

            return common.ERR_NONE
        except:
            traceback.print_exc()
            logE("Convert from db object failed, db password not correct?", TAG)
            return common.ERR_EXCEPTION
    
    def toKeyDB(self):
        from server.database.db_mgr import dbMgr
        try:
            signature = self.calcSignature()
            keyDB = Key(
                data_type = self.data_type,
                key_source = self.key_source,
                project = self.project if self.project is not None else "", # FIXME PLEASE
                model = self.model if self.model is not None else "", # FIXME PLEASE
                created_time = self.created_time,
                last_update_time = self.last_update_time,
                encrypted = True,

                name = dbMgr().encryptDataString2Base64(self.name) if self.name is not None and len(self.name) > 0 else "",
                tag = dbMgr().encryptDataString2Base64(self.tag) if self.tag is not None and len(self.tag) > 0 else "",
                alg = dbMgr().encryptDataString2Base64(self.alg) if self.alg is not None and len(self.alg) > 0 else "",
                # salt = "%s" % salt, # don't store to db, store to encrypted storage
                hint = dbMgr().encryptDataString2Base64(self.hint) if self.hint is not None and len(self.hint) > 0 else "",
                pwd = dbMgr().encryptDataString2Base64(self.pwd) if self.pwd is not None and len(self.pwd) > 0 else "", # backup in storage as well
                data = dbMgr().encryptDataString2Base64(self.data) if self.data is not None and len(self.data) > 0 else "",
                history = dbMgr().encryptDataString2Base64(self.history) if self.history is not None and len(self.history) > 0 else "",
                metadata = dbMgr().encryptDataString2Base64(self.metadata) if self.metadata is not None and len(self.metadata) > 0 else "",
                policy = dbMgr().encryptDataString2Base64(self.policy) if self.policy is not None and len(self.policy) > 0 else "",
                isdefault = self.isdefault,
                target_tool = self.target_tool,
                target_keytool = self.target_keytool,
                signature = signature,
                rootKeyId = str(self.rootKeyId),
                pubfids = self.pubfids if self.pubfids is not None and len(self.pubfids) > 0 else None,
                title = dbMgr().encryptDataString2Base64(self.title) if self.title is not None and len(self.title) > 0 else "",
            )
            return keyDB
        except:
            traceback.print_exc()
            logE("Convert to db object failed, db password not correct?", TAG)
            return None

    def validateSignature(self, signature=None):
        if (DEBUG): logD("validate validateSignature", TAG)

        signature2check = signature if signature is not None else self.signature
        calsignature = self.calcSignature()
        if signature2check is None or calsignature is None or signature2check != calsignature:
            logE("mistmatch signature, expected %s calc %s" % (signature2check, calsignature), TAG)
            return False

        return True

class KeyFileMeta:
    id = ""
    name = ""
    password = ""
    salt = ""
    fname = "" 
    type = "" # File type (pem, pub, plain, etc.)

    def __init__(self):
        self.id = ""
        self.name = ""
        self.password = ""
        self.salt = ""
        self.fname = ""

    # convert to json string, return json string on success, None otherwise
    def toJson(self):
        jdata = {
            "id":str(self.id),
            "name":self.name,
            "password":self.password,
            "salt":self.salt,
            "fname":self.fname,
            }
        try:
            jstring = json.dumps(jdata)
            return jstring
        except:
            traceback.print_exc()
            logE("Meta file: Convert to json failed", TAG)
            return None

    # parse json string, return ERR_NONE on success, error code otherwise
    def fromJson(self, val):
        try:
            jdata = json.loads(val)

            # parse data
            self.id = jdata["id"] if "id" in jdata else ""
            self.name = jdata["name"] if "name" in jdata else ""
            self.password = jdata["password"] if "password" in jdata else ""
            self.salt = jdata["salt"] if "salt" in jdata else ""
            self.fname = jdata["fname"] if "fname" in jdata else ""
            return common.ERR_NONE
        except:
            traceback.print_exc()
            logE("Meta file: Parse from json failed %s " % val, TAG)
            return common.ERR_EXCEPTION
