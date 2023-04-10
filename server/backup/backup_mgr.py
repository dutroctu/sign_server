#!/usr/bin/env python
#

# http://docs.mongoengine.org/apireference.html#fields
# https://flask-pymongo.readthedocs.io/en/latest/
# https://pythonbasics.org/flask-mongodb/
# http://docs.mongoengine.org/projects/flask-mongoengine/en/latest/

import os
import sys
import json

import traceback

# for testing purpose
# from server.app import getRootDataDir


from server.applog import log
from server.applog import logE
from server.applog import logD
from server import common as common

TAG = "BackupMgr"
BACKUP_DIRECTORY_NAME = ".backup"



class BackupMgr(object):
    from server.app import getRootDataDir
    BACKUP_DIRECTORY_DIRECTORY = os.path.join(getRootDataDir(), BACKUP_DIRECTORY_NAME)
    backupList = {}

    def registerBackup(self, backup):
        self.backupList[backup.getName()] = backup

    def getBackupDir(self, name):
        if name is not None:
            return os.path.join(BackupMgr.BACKUP_DIRECTORY_DIRECTORY, name)
        else:
            return ""

    def backup(self, password):
        for name, module in self.backupList.items():
            module.doBackup(self.getBackupDir(name))
        return common.ERR_NONE

    def restore(self):
        for name, module in self.backupList.items():
            module.doRestore(self.getBackupDir(name))
    
    def backupItem(self, module, data):
        return common.ERR_NONE

mgr = None

def backupMgr():
    global mgr
    if mgr == None:
        mgr = BackupMgr()
    return mgr

def init_backup_management(app = None):
    if (not os.path.exists(BackupMgr.BACKUP_DIRECTORY_DIRECTORY)):
        log("Make storage %s" % BackupMgr.BACKUP_DIRECTORY_DIRECTORY)
        os.makedirs(BackupMgr.BACKUP_DIRECTORY_DIRECTORY)
    else:
        log("Storage %s ready" % BackupMgr.BACKUP_DIRECTORY_DIRECTORY)