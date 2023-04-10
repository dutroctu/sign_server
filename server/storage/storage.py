#!/usr/bin/env python
#

# http://docs.mongoengine.org/apireference.html#fields
# https://flask-pymongo.readthedocs.io/en/latest/
# https://pythonbasics.org/flask-mongodb/
# http://docs.mongoengine.org/projects/flask-mongoengine/en/latest/
import os
from server import common as common
from server import applog as applog 

TAG = "IStorage"

# File encryption engine (abstract class)
class IStorage(object):

    # seup key, return ERR_NONE on success, error code otherwise
    def setKey(self, key, salt):
        applog.logE("setKey Not support", TAG)
        return common.ERR_NOT_SUPPORT

    # read and decrypt file, save to ofile.
    # return ERR_NONE on success, or error code otherwise. Exception may be raised in case of error
    # caller must make sure ofile not exist and folder to ofile already ready
    def readFile(self, ifile, ofile):
        applog.logE("readFile Not support", TAG)
        return common.ERR_NOT_SUPPORT

    # encrypt ifle and store to ofile
    # return ERR_NONE on success, or error code otherwise. Exception may be raised in case of error
    # caller must make sure ofile not exist and folder to ofile already ready
    def writeFile(self, ifile, ofile):
        applog.logE("writeFile Not support", TAG)
        return common.ERR_NOT_SUPPORT

    # encrypt buffer and store to ofile
    # return ERR_NONE on success, or error code otherwisee. Exception may be raised in case of error
    # caller must make sure ofile not exist and folder to ofile already ready
    def writeBuf2File(self, buf, ofile):
        applog.logE("writeBuf2File Not support", TAG)
        return common.ERR_NOT_SUPPORT

    # return name of engine, must be unquide in code
    def getName(self):
        return ""

