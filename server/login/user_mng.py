#!/usr/bin/env python
#
#  USE MANAGEMENT
#


from flask import Flask
from flask_restful import Api, Resource, reqparse
from flask import send_file
from flask import render_template
from flask import request, abort, jsonify, send_from_directory
# from server.app import app
import os
from server import applog as applog
from server.applog import logD
from server.applog import logE
from server.applog import log
from server import common as common
from server import hash as hash
import traceback
# from server.database.db_mgr.dbMgr import db
from server import database as database
from server.database.account import Account
from server.database.account import ACCOUNT_TYPE_ID_NAME
from server.database.account import ACCOUNT_STATUS_READY
from server.database.account import ACCOUNT_STATUS_NOT_READY
from server.database.account import ACCOUNT_STATUS_DEACTIVE
from server.database.account import ACCOUNT_STATUS_DELETE
from server.database.account import ACCOUNT_TYPE_ADMIN
from server.database.account import ACCOUNT_TYPE_SIGNER

# from server import login as login
from server.login.session import SessionMng
import server.database.db_mgr
import server.database.user_info
# from server.database.db_mgr.dbMgr import server.database.user_info.UserInfo
# from server.database.db_mgr.dbMgr import IDbListener
# from server.database.db_mgr.dbMgr import server.database.db_mgr.dbMgr
from datetime import datetime
from server.storage.storage_mgr import storageMgr
import tempfile
from server.app import DEBUG
from server import enc
from server.monitor.system_report import INCIDENT_SEVERITY_LOW, INCIDENT_SEVERITY_MIDDLE, sysReport

TAG = "UserMgr"

DEFAULT_ACCOUNT = "DEFAULT_ACCOUNT"
DEFAULT_PASSWORD = "DEFAULT_ACCOUNT"

DEFAULT_ROOT_ACCOUNT = "root"
DEFAULT_ROOT_PASSWORD = "r0ot@31"

MAX_FAILED_ATTEMPT = 3

MAX_LOCK_TIME_IN_SEC = 60

# Session managmeent
UserSessionList = SessionMng()


def hash_password(password, salt):
    return hash.sha1(bytes("password%s%s"%(password, salt), 'utf-8'))

#Factory to create corresponding signing module
# return ERR_NOT_FOUND if not found, ERR_EXISTED if exist, or other error code 
class UserMgr (database.db_mgr.IDbListener):
    is_ready = False

    def __init__(self):
        self.is_ready = False
        database.db_mgr.dbMgr().registerListener(self)

    def onChangePass(self, oldKey, oldIv, newKey, newIv):
        if (DEBUG): logD("onChangePass", TAG)
        items = Account.objects()
        from server.database.user_info import UserInfo
        for acc in items:
            
            if (DEBUG): logD("Change pass for acc id %s" % acc.id)

            if acc.encrypted and oldKey is None:
                logE("Failed to change pass, acc's data is encrypted, but no old pass set", TAG)
                return common.ERR_INVALID_DATA
            
            acc.username = database.db_mgr.dbMgr().reEncryptData(acc.username, oldKey, oldIv, newKey, newIv)
            acc.fullname = database.db_mgr.dbMgr().reEncryptData(acc.fullname, oldKey, oldIv, newKey, newIv) if acc.fullname is not None and len(str(acc.fullname)) > 0 else ""
            acc.email = database.db_mgr.dbMgr().reEncryptData(acc.email, oldKey, oldIv, newKey, newIv) if acc.email is not None and len(str(acc.email)) > 0 else ""
            acc.phone = database.db_mgr.dbMgr().reEncryptData(acc.phone, oldKey, oldIv, newKey, newIv) if acc.phone is not None and len(str(acc.phone)) > 0 else ""
            acc.password = database.db_mgr.dbMgr().reEncryptData(acc.password, oldKey, oldIv, newKey, newIv)
            acc.salt = database.db_mgr.dbMgr().reEncryptData(acc.salt, oldKey, oldIv, newKey, newIv)
            acc.history = database.db_mgr.dbMgr().reEncryptData(acc.history, oldKey, oldIv, newKey, newIv) if acc.history is not None and len(str(acc.history)) > 0 else ""
            acc.encrypted = True
            acc.signature = UserInfo().calcSignature(acc)
            acc.save()
        return common.ERR_NONE

    def getName(self):
        return "UserMgr"

    # check if user name exist
    def is_username_exist(self, name, ready_only=False):
        if (DEBUG): logD("is_username_exist %s, ready_only %d" % (name, ready_only))
        if (name is None or len(name) == 0):
            applog.logE("has no name")
            return common.ERR_INVALID_DATA
        
        if (DEBUG): logD("Search username %s" % name)
        enc_username = database.db_mgr.dbMgr().encryptDataString2Base64(name)
        if ready_only: # check with status of user
            acc = Account.objects(username=enc_username, status=ACCOUNT_STATUS_READY).first()
        else:
            acc = Account.objects(username=enc_username).first()

        if (acc is not None):
            return common.ERR_EXISTED
        
        return common.ERR_NOT_FOUND

    # Check if accout type exist and ready
    def is_acc_type_ready(self, type):
        if (DEBUG): logD("is_acc_type_ready %d" % type)
        if (type in ACCOUNT_TYPE_ID_NAME):
            acc = Account.objects(type=type, status=ACCOUNT_STATUS_READY).first()
            if (acc is not None):
                return common.ERR_EXISTED
            return common.ERR_NOT_FOUND
        else:
            return common.ERR_INVALID_ARGS

    # check if user name exist
    def is_userid_exist(self, id, ready_status_only=False):
        if (DEBUG): logD("is_userid_exist %s" % id)
        if (id is None):
            applog.logE("has no id")
            return common.ERR_INVALID_DATA
        
        if (DEBUG): logD("Search id %s" % id)
        if ready_status_only: # check with status of user
            acc = Account.objects(id=id, status=ACCOUNT_STATUS_READY).first()
        else:
            acc = Account.objects(id=id).first()

        if (acc is not None):
            return common.ERR_EXISTED
        
        return common.ERR_NOT_FOUND


    # create account, account NOT ACTIVE yet, MUST CALL activate accout api to active it
    # TODO: more user information, like note, etc.
    def create_account(self, username, account_type, password, fullname):
        if (DEBUG): logD("create_account usr %s type %d" % (username, account_type))
        if (username is not None) and len(username.strip()) > 0 and password is not None and len(password) > 0 and account_type in ACCOUNT_TYPE_ID_NAME:
            ret = self.is_username_exist(username)
            if (ret == common.ERR_NOT_FOUND):
                # TODO: validate info
                user_info = database.user_info.UserInfo()
                user_info.username = username.strip()
                user_info.fullname = fullname.strip()
                user_info.type = account_type
                
                # Hash password before saving to db
                user_info.salt = "%d" % common.get_randint()
                #TODO: check this again, should be HMAC?
                user_info.password = hash_password(password, user_info.salt)
                if (user_info.password is None):
                    applog.logE("Hash password failed")
                    return [common.ERR_FAILED, None]

                user_info.created_time = datetime.utcnow()
                user_info.default_password = True
                user_info.appendHistory("Create acc %s" % username)

                newacc = user_info.toDB()
                if (DEBUG): logD("save account %s" % user_info.username)
                try:
                    newacc.save() # save account to db
                except:
                    traceback.print_exc()
                    applog.logE("Save newacc failed")
                    return [common.ERR_FAILED, None]
                
                user_info.id = newacc
                user_info.account = newacc
                if (DEBUG): logD("Create account ok %s" % user_info.username)
                return [common.ERR_NONE, user_info]
            else:
                applog.logE("Check user name %d" % ret)
                return [ret, None]
        else:
            applog.logE("Invalid arg")
            return [common.ERR_INVALID_ARGS, None]

    # create account, account NOT ACTIVE yet, MUST CALL activate accout api to active it
    # TODO: more user information, like note, etc.
    def create_account2(self, user_info, random_pass=None):
        if (DEBUG): logD("create_account usr %s type %d" % (user_info.username, user_info.type))
        if (user_info is not None):
            ret = self.is_username_exist(user_info.username)
            if (ret == common.ERR_NOT_FOUND):
                # TODO: validate info
                user_info.status = ACCOUNT_STATUS_NOT_READY
                user_info.default_password = True
                # Hash password before saving to db
                user_info.salt = "%d" % common.get_randint()
                #TODO: check this again, should be HMAC?
                if random_pass is None:
                    random_pass = common.getRandomString()
                user_info.raw_password = random_pass
                user_info.password = hash_password(random_pass, user_info.salt)
                if (user_info.password is None):
                    applog.logE("Hash password failed")
                    return [common.ERR_FAILED, None]

                user_info.created_time = datetime.utcnow()
                user_info.appendHistory("Create new acc %s" % user_info.username)

                newacc = user_info.toDB()
                if (DEBUG): logD("save account %s" % user_info.username)
                try:
                    newacc.save() # save account to db
                except:
                    traceback.print_exc()
                    applog.logE("Save newacc failed")
                    return [common.ERR_FAILED, None]
                
                user_info.id = newacc
                user_info.account = newacc
                if (DEBUG): logD("Create account ok %s" % user_info.username)
                return [common.ERR_NONE, user_info]
            else:
                applog.logE("Check user name %d" % ret)
                return [ret, None]
        else:
            applog.logE("Invalid arg")
            return [common.ERR_INVALID_ARGS, None]

    # activate account
    def activate_account(self, username, userid=None, activate=1):
        if (DEBUG): logD("activate_account %s, activate: %d" % (username, activate))
        enc_username = database.db_mgr.dbMgr().encryptDataString2Base64(username)
        user = Account.objects(username=enc_username).first()
        if (user is None):
            applog.logE("username %s not found" % username)
            return [common.ERR_NOT_FOUND, None]
        if userid is not None and user.id is not None and str(userid).strip().lower() != str(user.id).strip().lower():
            applog.logE("mistmatch userid and user name (%s vs %s)" % (userid, user.id))
            return [common.ERR_NOT_MATCH, None]
        try:
            userinfo = database.user_info.UserInfo(user)
            status = ACCOUNT_STATUS_READY if activate == 1 else ACCOUNT_STATUS_DEACTIVE
            if status == ACCOUNT_STATUS_DEACTIVE and not self.allow_to_change(userinfo):
                return [common.ERR_PROHIBIT, "not allow to change this account"]
            ret = userinfo.updateStatus(status, updateDB=True)
        except:
            traceback.print_exc()
            applog.logE("Update acc status failed")
            return [common.ERR_FAILED, None]
        
        return [ret, userinfo]

    def add_rsa(self, userid, rsa):
        if (DEBUG): logD("add_rsa %s, rsa: %s" % (userid, rsa))
        if rsa is None or len(rsa) == 0:
            logE("Invalid RSA value to add", TAG)
            return [common.ERR_INVALID_ARGS, "Invalid rsa"]
        user = Account.objects(id=userid).first()
        if (user is None):
            applog.logE("userid %s not found" % userid)
            return [common.ERR_NOT_FOUND, None]
        ret = enc.ssh_rsa_verify_id_rsa(rsa)
        if ret != common.ERR_NONE:
            logE("Invalid input rsa %s" % rsa, TAG)
            return [common.ERR_INVALID_DATA, "Invalid data"]
        try:
            userinfo = database.user_info.UserInfo(user)

            if userinfo.status != ACCOUNT_STATUS_READY:
                return [common.ERR_PROHIBIT, "Acc not ready"]

            found = False
            if userinfo.sshrsa is not None and len(userinfo.sshrsa) > 0:
                for fid in userinfo.sshrsa:
                    if fid is not None and len(fid) > 0:
                        f = tempfile.NamedTemporaryFile()
                        ret = storageMgr().readFile(fid, f.name)
                        if (DEBUG): logD("tempfile %s" % f.name, TAG )
                        if ret == common.ERR_NONE:
                            tmprsa = common.read_string_from_file(f.name)
                            if (DEBUG): logD("tmprsa %s" % tmprsa, TAG)
                            if tmprsa is not None and len(tmprsa) > 0 and tmprsa == rsa:
                                found = True
                                break
                        f.close()
            if not found:
                [ret, meta, fid] = storageMgr().writeBuf2File(bytes(rsa, 'utf-8'))

                if ret is not None and fid is not None:
                    ret = userinfo.appendRsa(fid, updateDB=True)
            else:
                applog.logE("rsa already exist", TAG)
                return [common.ERR_EXISTED, None]
        except:
            traceback.print_exc()
            applog.logE("add rsa failed", TAG)
            return [common.ERR_FAILED, None]
        
        return [ret, userinfo]

    def get_rsa(self, username=None, userid=None):
        if (DEBUG): logD("get_rsa %s" % (username))
        if userid is not None:
            user = Account.objects(id=userid).first()
        elif username is not None:
            enc_username = database.db_mgr.dbMgr().encryptDataString2Base64(username)
            user = Account.objects(username=enc_username).first()
        else:
            logE("get_rsa Invalid username/userid", TAG)
            return None
        rsaList = {}
        if (user is None):
            logE("userid %s not found" % userid)
            return None
        try:
            userinfo = database.user_info.UserInfo(user)

            if userinfo.status != ACCOUNT_STATUS_READY:
                logE("Acc not ready", TAG)
                return None
            if userinfo.sshrsa is not None and len(userinfo.sshrsa) > 0:
                import tempfile
                for fid in userinfo.sshrsa:
                    f = tempfile.NamedTemporaryFile()
                    ret = storageMgr().readFile(fid, f.name)
                    if ret == common.ERR_NONE:
                        rsa = common.read_string_from_file(f.name)
                        rsaList[fid] = rsa
                    f.close()
        except:
            traceback.print_exc()
            logE("get_rsa failed")
            return None
        
        return rsaList

    def del_rsa(self, userid, rsafid):
        if (DEBUG): logD("del_rsa %s, rsafid: %s" % (userid, rsafid))
        user = Account.objects(id=userid).first()
        if (user is None):
            applog.logE("userid %s not found" % userid)
            return [common.ERR_NOT_FOUND, None]
        try:
            userinfo = database.user_info.UserInfo(user)
            if userinfo.status != ACCOUNT_STATUS_READY:
                return [common.ERR_PROHIBIT, "Acc not ready"]
            if rsafid is not None:
                ret = userinfo.delRsa(rsafid, updateDB=True)
                ret = storageMgr().delete(rsafid)
        except:
            traceback.print_exc()
            applog.logE("del_rsa failed")
            return [common.ERR_FAILED, None]
        
        return [ret, userinfo]


    # reset password of account
    def reset_password(self, username, userid=None):
        if (DEBUG): logD("activate_account %s" % username)
        enc_username = database.db_mgr.dbMgr().encryptDataString2Base64(username)
        user = Account.objects(username=enc_username).first()
        user_info = None
        if (user is None):
            applog.logE("username %s not found" % username)
            return [common.ERR_NOT_FOUND, None]
        if userid is not None and user.id is not None and str(userid).strip().lower() != str(user.id).strip().lower():
            applog.logE("mistmatch userid and user name (%s vs %s)" % (userid, user.id))
            return [common.ERR_NOT_MATCH, None]
        try:
            # user.update(status = ACCOUNT_STATUS_READY) # update status
            user_info = database.user_info.UserInfo(user)
            user_info.default_password = True
            # Hash password before saving to db
            user_info.salt = "%d" % common.get_randint()
            random_pass = common.getRandomString()
            user_info.password = hash_password(random_pass, user_info.salt)
            if (user_info.password is None):
                applog.logE("Hash password failed")
                return [common.ERR_FAILED, None]
            user_info.raw_password = random_pass
            user_info.appendHistory("Reset password")
            updateacc = user_info.toDB(createNew = False)
            applog.log("update password for account %s" % user_info.username, TAG)
            try:
                updateacc.save()
            except:
                traceback.print_exc()
                applog.logE("Update acc failed")
                return [common.ERR_FAILED, None]
        except:
            traceback.print_exc()
            applog.logE("Update acc status failed")
            return [common.ERR_FAILED, None]
        
        return [common.ERR_NONE, user_info]

    #
    # Change account password
    # FIXME: it's based on username, should be userid??????
    def change_password(self, username, oldPass, newPassword):
        applog.log("change_password %s" % username)
        enc_username = database.db_mgr.dbMgr().encryptDataString2Base64(username)
        user = Account.objects(username=enc_username).first()
        user_info = None

        if (user is None):
            applog.logE("username %s not found" % username)
            return common.ERR_NOT_FOUND
        try:
            user_info = database.user_info.UserInfo(user)
            
            # old pass
            oldHashPass = hash_password(oldPass, user_info.salt)

            # check oldpass match one in db first
            if (str(oldHashPass).strip().lower() != str(user_info.password).strip().lower()):
                logE("Old Password not match")
                return common.ERR_NOT_MATCH

            
            # Hash password before saving to db
            newSalt = "%d" % common.get_randint()
            newHashPass = hash_password(newPassword, newSalt)
            
            user_info.salt = newSalt
            user_info.password = newHashPass

            if (user_info.password is None):
                applog.logE("Hash password failed")
                return [common.ERR_FAILED, None]

            # ok to update db
            user_info.default_password = False
            user_info.appendHistory("Change password")
            updateacc = user_info.toDB(createNew = False)
            applog.log("update password for account %s" % user_info.username, TAG)
            try:
                updateacc.save()
            except:
                traceback.print_exc()
                applog.logE("Update acc failed")
                return common.ERR_FAILED
        except:
            traceback.print_exc()
            applog.logE("Update acc status failed")
            return common.ERR_FAILED
        
        return common.ERR_NONE

    #
    # Allow to update this user?
    # Return True if allow, False if not allow
    #
    def allow_to_change(self, userinfo):
        if (DEBUG): logD("allow_to_change %s" % userinfo.username)
        # if acc admin is changed, but only one admin account is actived, not allow to change
        if userinfo.type == ACCOUNT_TYPE_ADMIN:
            no_admin = Account.objects(type=ACCOUNT_TYPE_ADMIN, status=ACCOUNT_STATUS_READY).count()
            if (DEBUG): logD("no_admin %d" % no_admin)
            if (no_admin < 2):
                logE("This is only one admin account, not allow to update")
                return False
        
        return True

    #
    # Delete account
    #
    def delete_account(self, username, userid=None, force=False):
        if (DEBUG): logD("delete_account %s, force %d" % (username, force))
        enc_username = database.db_mgr.dbMgr().encryptDataString2Base64(username)
        user = Account.objects(username=enc_username).first()
        if (user is None):
            applog.logE("username %s not found" % username)
            return common.ERR_NOT_FOUND
        if userid is not None and user.id is not None and str(userid).strip().lower() != str(user.id).strip().lower():
            applog.logE("mistmatch userid and user name (%s vs %s)" % (userid, user.id))
            return common.ERR_NOT_MATCH
        try:
            userinfo = database.user_info.UserInfo(user)

            # allow to change?
            if not self.allow_to_change(userinfo):
                return common.ERR_PROHIBIT
                
            if (not force):
                userinfo.updateStatus(status = ACCOUNT_STATUS_DELETE, updateDB=True) # update status
            else:
                user.delete()
        except:
            traceback.print_exc()
            applog.logE("Delete acc failed")
            return common.ERR_FAILED
        
        return common.ERR_NONE

    #
    # Update user info
    #
    def updateUserInfo(self, newuserinfo):
        applog.log("updateUserInfo %s" % newuserinfo.id)
        if (newuserinfo.id is None or len(newuserinfo.id) == 0):
            applog.logE("invalid userid")
            return common.ERR_INVALID_ARGS
        # enc_username = database.db_mgr.dbMgr().encryptDataString2Base64(username)
        user = Account.objects(id=newuserinfo.id).first()
        if (user is None):
            applog.logE("user id %s not found" % newuserinfo.id)
            return common.ERR_NOT_FOUND
        try:
            userinfo = database.user_info.UserInfo(user)
            # user.update(status = ACCOUNT_STATUS_READY) # update status
            if (userinfo.username != newuserinfo.username):
                applog.logE("miss match user name (%s vs %s)" % (newuserinfo.username, userinfo.username))
                return common.ERR_NOT_MATCH

            userinfo.appendHistory("Update user info")
            userinfo.fullname = newuserinfo.fullname
            userinfo.email = newuserinfo.email
            userinfo.phone = newuserinfo.phone
            userinfo.note = newuserinfo.note

            # allow to change?
            if (userinfo.type == ACCOUNT_TYPE_ADMIN) and (newuserinfo.type != ACCOUNT_TYPE_ADMIN):
                if not self.allow_to_change(userinfo):
                    return common.ERR_PROHIBIT
            
            userinfo.type = newuserinfo.type
            try:
                userdb = userinfo.toDB(createNew=False)
                if userdb is not None:
                    userdb.save()
                else:
                    raise ValueError("Faile to convert to userdb")
            except:
                traceback.print_exc()
                applog.logE("Update acc failed")
                return common.ERR_EXCEPTION
        except:
            traceback.print_exc()
            applog.logE("Update acc status failed")
            return common.ERR_FAILED
        
        return common.ERR_NONE

    # get user info
    def get_userinfo(self, username):
        if (DEBUG): logD("get_userinfo")
        if (username is not None) and len(username) > 0:
            if (DEBUG): logD("Search username %s" % username, TAG)
            # encrypt user name first
            enc_username = database.db_mgr.dbMgr().encryptDataString2Base64(username)
            if enc_username is not None:
                # check user with ready state
                acc = Account.objects(username=enc_username, status=ACCOUNT_STATUS_READY).first()
                if (acc is not None):
                    if (acc.status == ACCOUNT_STATUS_READY):
                        return database.user_info.UserInfo(acc) # well done
                    else:
                        applog.logE("Account %s is inactive" % username, TAG)
                else:
                    logE("get user failed, not found account", TAG)
            else:
                logE("get userinfo failed encrypt data failed", TAG)
        else:
            logE("get userinfo failed, Invalid user name", TAG)
        return None

    # get user info
    def get_user_from_id(self, userid, status=[ACCOUNT_STATUS_READY,ACCOUNT_STATUS_DEACTIVE]):
        if (DEBUG): logD("get_user_from_id")
        if (userid is not None) and len(userid) > 0:
            if (DEBUG): logD("Search userid %s" % userid)
            acc = Account.objects(id=userid, status__in=status).first()
            if (acc is not None):
                return database.user_info.UserInfo(acc)
        return None

    # get account status, return array of [error coce, message]
    def get_account_status(self, name):
        ret = common.ERR_FAILED
        msg = "Failed"
        if (DEBUG): logD("get_account_status %s" % name)
        if (name is None or len(name) == 0):
            msg = "has no name"
            ret = common.ERR_INVALID_DATA
        if (DEBUG): logD("Search username %s" % name)
        enc_username = database.db_mgr.dbMgr().encryptDataString2Base64(name)
        if (DEBUG): logD("enc_username %s" % enc_username)
        acc = Account.objects(username=enc_username).first()
        if (acc is not None):
            user_info = database.user_info.UserInfo(acc)
            if (DEBUG): logD("%s" % user_info.toString())

            if (user_info.status == ACCOUNT_STATUS_READY):
                fail_cnt = user_info.getFailAttempt()
                if (fail_cnt > MAX_FAILED_ATTEMPT):
                    msg = "Acc %s is locked, failed %d" % (name, fail_cnt)
                    ret = common.ERR_LOCKED
            else:
                applog.logE("Account %s is not ready, state %d" % (name, user_info.status))
                msg = "Acc %s is not ready" % name
                ret = common.ERR_NOT_READY

        else:
            msg = "Not found %s" % name
            ret = common.ERR_NOT_FOUND
        
        return [ret, msg]

    # check account basing on name and password, return user info if ok
    # requester: string to describe about requester
    def check_account(self, name, password, status=ACCOUNT_STATUS_READY, requester=None):
        log("check_account %s" % name, TAG)
        if (name is None or len(name) == 0):
            applog.logE("has no name", TAG)
            return [common.ERR_INVALID_DATA, None]
        
        if (DEBUG): log("Search username %s" % name, TAG)
        enc_username = database.db_mgr.dbMgr().encryptDataString2Base64(name)

        if (DEBUG): logD("enc_username %s" % enc_username, TAG)
        acc = Account.objects(username=enc_username, status=status).first()
        if (acc is not None):
            user_info = database.user_info.UserInfo(acc)
            if (DEBUG): logD("%s" % user_info.toString(), TAG)
            if (user_info.status == ACCOUNT_STATUS_READY):
                # check failed attemp
                fail_cnt = user_info.getFailAttempt()
                if (DEBUG): logD("current fail_cnt %d" % (fail_cnt), TAG)

                currtime = datetime.utcnow()
                delta = 0
                if (user_info.last_login_time is not None and (currtime > user_info.last_login_time)):
                    delta = (currtime - user_info.last_login_time).total_seconds() if user_info.last_login_time is not None else 0
                if (DEBUG): logD("currtime %s" % str(currtime), TAG)
                if (DEBUG): logD("last_login_time %s" % str(user_info.last_login_time), TAG)
                if (DEBUG): logD("delta %d sec" % delta, TAG)

                user_info.updateLastLoginTime()
                if (fail_cnt > MAX_FAILED_ATTEMPT):
                    # already reach max failed attempt, now, try to check if it's over lock time
                    applog.logE("Account %s is locked, failed attemp %d" % (name, fail_cnt))

                    if delta > MAX_LOCK_TIME_IN_SEC: # read max wait time, decrease counter into one
                        log("reach max waiting time, reduce fail attemp 1 to continue checking", TAG)
                        user_info.incFailAttempt(inc=False, msg = ("Src: %s" % requester) if requester is not None else "")
                    else:
                        logE("not reach max wait time. waited %d sec, continue waiting" % delta, TAG)
                        return [common.ERR_LOCKED, None]

                hash_pass = hash_password(password, user_info.salt)
                # enc_pass = database.db_mgr.dbMgr().encryptDataString2Base64(hash_pass)
                if (hash_pass == user_info.password):
                    if user_info.validateSignature():
                        applog.log("Account %s is OK" % name, TAG) # ALL OK
                        
                        # return [common.ERR_NONE, UserMgr.acc_to_userinfo(acc)]
                        if (fail_cnt > 0):
                            user_info.clearFailAttempt(("Src: %s" % requester) if requester is not None else "")
                        user_info.appendHistory("Login ok from %s " % ("Src: %s" % requester) if requester is not None else "", updateDB=True)
                        return [common.ERR_NONE, user_info]
                    else:
                        applog.logE("Account %s is OK, but signature is not OK" % name, TAG, True) # ALL OK
                        # return [common.ERR_NONE, UserMgr.acc_to_userinfo(acc)]
                        sysReport().reportIncident(INCIDENT_SEVERITY_MIDDLE, requester, "Login ok, but check acc signature failed")
                        return [common.ERR_CORRUPT, None]
                else:
                    if (DEBUG): logD("%s vs %s" % (hash_pass, user_info.password))
                    applog.logE("%s Password not match" % name, TAG)
                    user_info.incFailAttempt(msg = ("Src: %s" % requester) if requester is not None else "")
                    fail_cnt = user_info.getFailAttempt()
                    sysReport().reportIncident(INCIDENT_SEVERITY_MIDDLE, requester, "Login with wrong password, tried %d" % fail_cnt)

                    if (DEBUG): logD("fail_cnt %d" % (fail_cnt), TAG)
                    if (fail_cnt > MAX_FAILED_ATTEMPT):
                        applog.logE("Account %s is locked, failed attemp %d" % (name, fail_cnt), TAG)
                        return [common.ERR_LOCKED, None]
                    else:
                        return [common.ERR_NOT_MATCH, None]
            else:
                applog.logE("Account %s is inactive" % name, TAG)
                return [common.ERR_INACTIVE, None]

        if (DEBUG): logD("Account %s not found" % name, TAG)
        return [common.ERR_NOT_FOUND, None]


    def get_all_users(self, includeDelete=False):
        user_list = []
        if (DEBUG): logD("get_all_users")
        if not includeDelete:
            items = Account.objects(status__ne=ACCOUNT_STATUS_DELETE)
        else:
            items = Account.objects()
        
        
        if (DEBUG): logD("found %d account, convert to user info" % len(items))

        for item in items:
            user_list.append(database.user_info.UserInfo(acc=item))

        if (DEBUG): logD("found %d user" % len(user_list))
        return user_list


g_usrMgr = None

def usrMgr():
    global g_usrMgr
    if g_usrMgr is None:
        g_usrMgr = UserMgr()
    return g_usrMgr

# init user management
def init_user_management(app = None):
    applog.log("init_user_management", TAG, toFile=True)
    
    usrMgr()

    return common.ERR_NONE

# init user management
def setup_user_management(app = None):
    applog.log("setup_user_management", TAG, toFile=True)

    # Check if default account exist, if not, create new one with default password
    # TODO: IS IT SAFE?

    log("Check admin account")
    acc_exist = usrMgr().is_acc_type_ready(ACCOUNT_TYPE_ADMIN)
    if (acc_exist == common.ERR_NOT_FOUND):
        applog.log("Not Found admin account %s, create new one with default info" % DEFAULT_ROOT_ACCOUNT, TAG, True)
        [ret, user] = usrMgr().create_account(DEFAULT_ROOT_ACCOUNT, ACCOUNT_TYPE_ADMIN, DEFAULT_ROOT_PASSWORD, DEFAULT_ROOT_ACCOUNT)
        if (ret == common.ERR_NONE):
            [ret, user] = usrMgr().activate_account(DEFAULT_ROOT_ACCOUNT)
    else:
        applog.log("Found admin account")
        ret = common.ERR_NONE

    acc_exist = usrMgr().is_acc_type_ready(ACCOUNT_TYPE_SIGNER)
    
    # log("Check signer account")
    # if ret == common.ERR_NONE:
    #     if (acc_exist == common.ERR_NOT_FOUND):
    #         applog.log("Not Found signer account %s, create new one with default info" % DEFAULT_ACCOUNT, TAG, True)
    #         [ret, user] = usrMgr().create_account(DEFAULT_ACCOUNT, ACCOUNT_TYPE_ADMIN, DEFAULT_PASSWORD, DEFAULT_ACCOUNT)
    #         if (ret == common.ERR_NONE):
    #             [ret, user] = usrMgr().activate_account(DEFAULT_ACCOUNT)
    #     else:
    #         applog.log("Found signer account")
    #         ret = common.ERR_NONE

    return ret

