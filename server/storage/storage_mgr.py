#!/usr/bin/env python
#

# http://docs.mongoengine.org/apireference.html#fields
# https://flask-pymongo.readthedocs.io/en/latest/
# https://pythonbasics.org/flask-mongodb/
# http://docs.mongoengine.org/projects/flask-mongoengine/en/latest/

import os
import sys
from server.storage.storage_aes_crypt import StorageAesCrypImpl
import json

import traceback
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from Crypto.Random import get_random_bytes
import tempfile
import shutil
from server.app import DEBUG
# for testing purpose
from server.app import getRootDataDir
from server.app import is_debug


from server.applog import log
from server.applog import logE
from server.applog import logD
from server import common as common
from server import hash as hash
from server import enc as enc
import server.monitor.system_report
from server.backup.backup import IBackup


TAG = "StorageMgr"
ENC_STORAGE_DIRECTORY_NAME = ".encstorage" # origin/main directory name

# new name for change password, temporary folder, will be changed to main name after finish
ENC_STORAGE_DIRECTORY_NEW_NAME = ".encstorage_new" 

# File extenstion of encrypted file
ENC_STORAGE_ENC_FNAME_EXT = "enc"
# File extenstion of raw file
ENC_STORAGE_RAW_FNAME_EXT = "dec"
# File extenstion of meta file of encrypted file
ENC_STORAGE_META_FNAME_EXT = "meta"

# File extenstion of meta file of storage
ENC_STORAGE_META_FNAME = "meta"

ENC_STORAGE_DELETE_DIR_FNAME = "deleted"


HASH_ALGO = hash.ALGO_SHA256
ENCRYPT_ALGO = enc.ALGO_AES_256_CBC

# encrypted file is identified by fid (file id), built basing on original path + tag
# storage: root
#            |-- encstorage
#                     |-- deleted --> for deleted files
#                     |-- <list of file <id>.enc
#                     |-- <list of metafile <id>.meta
#                     |-- log_file --> log file
#                     |-- meta  ---------------------> IMPORTANT FILE, IT CONTAINS SALT TO BUILD FINALY ENCRYPTION KEY


ENC_STORAGE_DIRECTORY = os.path.join(getRootDataDir(), ENC_STORAGE_DIRECTORY_NAME)
ENC_STORAGE_DELETE_DIR = os.path.join(ENC_STORAGE_DIRECTORY, ENC_STORAGE_DELETE_DIR_FNAME)

###########################################################################
#
# Meta data of encrypted files
#
###########################################################################
class EncFileMeta:
    # plain
    hash_algo = "" # hash algorithm to be used
    encrypt_algo = "" # encryption algorithm to be used
    iv = "" # init vector
    sig = "" # signature, hmac of password and cipher test data
    engine = "" # crypto engine to be used
    create_date = "" # create date of file

    # data should be encrypted:
    fname = "" # original file path
    tag = "" # Tag
    hash_plain = "" # hash of plain text
    metaInfo="" # provided by caller, in string format, will be encrypted

    def __init__(self):
        self.hash_algo = ""
        self.encrypt_algo = ""
        self.iv = ""
        self.sig = ""
        self.engine = ""
        self.create_date = ""
        self.fname = ""
        self.tag = ""
        self.hash_plain = ""
        self.metaInfo = ""

    # convert to json string, return json string on success, None otherwise
    def toJson(self):
        jdata = {
            "tag":self.tag,
            "hash_plain":self.hash_plain,
            "fname":self.fname,
            "hash_algo":self.hash_algo,
            "encrypt_algo":self.encrypt_algo,
            "iv":self.iv,
            "sig":self.sig,
            "engine":self.engine,
            "create_date":self.create_date,
            "metaInfo":self.metaInfo,
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
            self.tag = jdata["tag"] if "tag" in jdata else ""
            self.hash_plain = jdata["hash_plain"] if "hash_plain" in jdata else ""
            self.fname = jdata["fname"] if "fname" in jdata else ""
            self.hash_algo = jdata["hash_algo"] if "hash_algo" in jdata else ""
            self.encrypt_algo = jdata["encrypt_algo"] if "encrypt_algo" in jdata else ""
            self.iv = jdata["iv"] if "iv" in jdata else ""
            self.sig = jdata["sig"] if "sig" in jdata else ""
            self.create_date = jdata["create_date"] if "create_date" in jdata else ""
            self.engine = jdata["engine"] if "engine" in jdata else ""
            self.metaInfo = jdata["metaInfo"] if "metaInfo" in jdata else ""
            return common.ERR_NONE
        except:
            traceback.print_exc()
            logE("Meta file: Parse from json failed %s " % val, TAG)
            return common.ERR_EXCEPTION

###########################################################################
#
# Meta data of storage management
#
###########################################################################
class StorageMgrMeta:
    keyHashBase64 = "" # hash of final encryption key
    ivStringBase64 = "" # common iv used to encrypt/decrypt data
    saltStringBase64 = "" # common salt, used with key to generate final key
    default_engine = "" # name of default file encryption engine to be used

    def __init__(self):
        self.keyHashBase64 = ""
        self.ivStringBase64 = ""
        self.saltStringBase64 = ""
        self.default_engine = ""
    
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
            logE("Meta storage: Convert to json failed", TAG)
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
            logE("Meta storage: Parse from json failed %s " % val, TAG)
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


class IStorageListener(object):
    def getName(self):
        return None

    def onFileDeleted(self, fid):
        if (DEBUG): logD("onFileDeleted %s, fid %s" % (self.getName(), fid), TAG)
        return common.ERR_NONE

###########################################################################
#
# Storage Management
#
###########################################################################
class StorageMgr(IBackup):

    storage_impl = None # Encryption engine to be used
    key = None # final key used to encyrpt/decrypt file
    meta = None # storage meta info
    is_ready = False


    # FIXME
    # TODO: this is just temporary implemenation, to save decrypt one to temp dir. 
    # IDEA: should make virtual disk with encryption?
    # https://www.tecmint.com/create-virtual-harddisk-volume-in-linux/
    # https://leewc.com/articles/how-to-set-up-virtual-disk-encryption-linux/
    # key is fid, value is array, 1st element is path, 2nd element is created time
    tempfileList = {} 
    DEFAULT_AUTO_CLEAR_TEMP_FILE_MS = 5 * 60 * 1000 # 5'
    temp_dir = None
    root_tmp_dir = None
    listeners = []
    def __init__(self, storage_impl):
        self.storage_impl = storage_impl
        self.key = None
        self.meta = None
        self.is_ready = False
        self.tempfileList = {}
        self.temp_dir = None
        self.root_tmp_dir = None
        self.listeners = []

    def exit(self):
        log("EXIT!", TAG)
        # clean up temp file
        self.checkToClearTemp()
        
        self.is_ready = False
        self.key = None

        common.rmdirs(self.root_tmp_dir)

    def registerListener(self, listener):
        if listener is not None and listener.getName() is not None:
            log("Register listener %s" % listener.getName(), TAG)
            self.listeners.append(listener)
        else:
            logE("Register listener failed, not set name?", TAG)
            return common.ERR_FAILED

    def isPasswordSet(self):
        log("check if password set", TAG)
        metaFile = self.getStorageMgrMetaPath()
        if (not os.path.exists(metaFile)):
            logE("Not set yet", TAG)
            return False
        log("already set", TAG)
        return True

    # setup storage
    # pws is intialize password, final one to be used is KDF between pwd and salt
    # return ERR_NONE on success, error code otherwise
    def setup(self, pwd):
        # logD("base64 %s" % base64.urlsafe_b64encode(key).decode())
        salt = ""
        log("setup", TAG)
        if pwd is None or len(pwd) == 0:
            logE("setup storage failed, invalid pass")
            return common.ERR_INVALID_ARGS

        if self.storage_impl is None:
            logE("unknown encryption engine")
            return common.ERR_NOT_READY
        metaFile = self.getStorageMgrMetaPath()

        # metaFile not exist, create new one
        if (not os.path.exists(metaFile)):
            try:
                storageMgrMeta = StorageMgrMeta()
                
                # generate random iv
                iv = get_random_bytes(enc.AES_BLOCK_SIZE_BYTE)
                # convert to base64 string
                storageMgrMeta.ivStringBase64 = common.encodeBase64(iv)

                # generate random salt
                salt = get_random_bytes(enc.AES_BLOCK_SIZE_BYTE)
                # convert to base64 string
                storageMgrMeta.saltStringBase64 = common.encodeBase64(salt)

                # calc final key encryption key
                key = hash.kdfFromString(pwd, storageMgrMeta.saltStringBase64)
                key_hash = common.encodeBase64(hash.hashVal(key, hash.ALGO_SHA256))

                storageMgrMeta.keyHashBase64 = key_hash
                
                jdata = storageMgrMeta.toJson()
                # logD(jdata)
                if (jdata is not None):
                    ret = common.write_string_to_file(metaFile, jdata)
                    if (not ret):
                        logE("Write storage meta to file failed", TAG)
                        return common.ERR_FAILED
                else:
                    return common.ERR_FAILED
            except:
                traceback.print_exc()
                logE("Build storage meta failed", TAG)
                return common.ERR_EXCEPTION

        # well done, let's read meta file
        metaString = common.read_string_from_file(metaFile)
        if metaString is None or len(metaString) == 0:
            logE("Read storage meta failed, not data", TAG)
            return common.ERR_NO_DATA
        
        # parse meta info
        jmeta = StorageMgrMeta()
        ret = jmeta.fromJson(metaString)
        if ret != common.ERR_NONE:
            logE("Parse storage meta failed", TAG)
            return ret

        # FIXME: safe to print info here????
        if (DEBUG): logD("storage meta %s" % jmeta.toJson())

        # calculate key encryption key and key hash
        self.key = hash.kdfFromString(pwd, jmeta.saltStringBase64)
        key_hash = common.encodeBase64(hash.hashVal(self.key, hash.ALGO_SHA256))

        # check if key are matched
        if (key_hash == jmeta.keyHashBase64):
            log("Key encryption Key OK", TAG)
        else:
            logE("key not match, expect %s, real %s" % (key_hash, jmeta.keyHashBase64), TAG)
            return common.ERR_NOT_MATCH
        

        ret = self.storage_impl.setKey(pwd, jmeta.saltStringBase64)
        if ret != common.ERR_NONE:
            logE("Set key for encryption engine failed", TAG)
            return ret
        
        self.meta = jmeta
        
        # clean up temp file
        # self.checkToClearTemp()

        # all well done, hope so
        self.is_ready = True

        # Check to clear tmp dir
        if (DEBUG): logD("key_hash %s" % key_hash)
        system_tem_dir = tempfile.gettempdir()
        self.root_tmp_dir = os.path.join(system_tem_dir, key_hash)
        if os.path.exists(self.root_tmp_dir):
            common.rmdirs(self.root_tmp_dir)
        
        os.makedirs(self.root_tmp_dir)
        self.temp_dir = tempfile.mkdtemp(dir=self.root_tmp_dir)
        if (DEBUG): logD("temp_dir %s" % self.temp_dir)

        # raise ValueError("temp_dir %s" % temp_dir)

        log("Storage Management is ready to use", TAG)
        return common.ERR_NONE


    # FIXME
    # TODO: this is just temporary implemenation, to save decrypt one to temp dir. 
    # IDEA: should make virtual disk with encryption?
    # https://www.tecmint.com/create-virtual-harddisk-volume-in-linux/
    # https://leewc.com/articles/how-to-set-up-virtual-disk-encryption-linux/
    
    # Create temporary file, add to temp list, return tempPath if ok, None on error
    def createTmpFile(self, fid):
        if (DEBUG): logD("addToTempList %s" % fid, TAG)
        if fid is not None:
            # check if fid already in templist, remove old one
            # TODO and FIXME: concurrent access?
            if fid in self.tempfileList:
                [path, time] = self.tempfileList[fid]
                if path is not None and len(path) > 0 and os.path.exists(path):
                    os.remove(path)
        
            # create temp file
            try:
                log("temp_dir %s" % self.temp_dir)
                visible = tempfile.NamedTemporaryFile(delete=False, dir=self.temp_dir) # not auto delete
                tempPath = visible.name
                visible.close()
            except:
                traceback.print_exc()
                logE("Failed to create temp file for fid %s" % fid, TAG)
                return None
            
            if tempPath is not None:
                if (DEBUG): logD("temp file for fid %s path %s" % (fid, tempPath))
                # add to list for management
                self.tempfileList[fid] = [tempPath, common.current_milli_time()]

                # check to clear
                # TODO: make timer to auto clear
                self.checkToClearTemp([fid])

                return tempPath
            else:
                logE("Failed to create temp file for fid %s" % fid, TAG)
                return None
        else:
            logE("failed to add templist, invalid arg", TAG)
            return None
    

        

    # Retreive file name via fid, return path  if exist, None on error
    def getTmpFilePath(self, fid):
        if (DEBUG): logD("getFilePath %s" % fid, TAG)
        if fid is not None and fid in self.tempfileList:
            [path, time] = self.tempfileList[fid]
            if (DEBUG): logD("path %s time %d" % (fid, time), TAG)

            # check to clear, ignore this fid
            self.checkToClearTemp([fid])
            return path
        else:
            logE("Not found fid %s" % fid, TAG)
            return None

    # remove temporary file via fid
    def removeTempFile(self, fid, check2Clear=True):
        if (DEBUG): logD("removeTempFile %s" % fid, TAG)
        if fid is not None and fid in self.tempfileList:
            [path, time] = self.tempfileList[fid]
            
            if (DEBUG): logD("found one, remove %s" % path, TAG)
            # remove file
            if path is not None and len(path) > 0 and os.path.exists(path):
                os.remove(path)

            # clear fid in list
            self.tempfileList[fid] = None

            del self.tempfileList[fid]

            if check2Clear:
                self.checkToClearTemp([fid])
            else:
                self.dumpTempList() # dump to check


            return common.ERR_NONE
        else: # not foud
            logE("Not found fid %s" % fid, TAG)
            return common.ERR_NOT_FOUND

    # dump list, for debug purpuse only
    def dumpTempList(self):
        if is_debug():
            if (DEBUG): logD("temp list %s" % self.tempfileList, TAG)

    # check to clear temp
    # TODO: make timer to auto clean?
    # TODO: this is just temporary implemenation, to save decrypt one to temp dir. 
    def checkToClearTemp(self, ignoreFids = []):
        if (DEBUG): logD("checkToClearTemp ignoreFids %s" % ignoreFids, TAG)
        curren_time = common.current_milli_time()
        if (DEBUG): logD("curren_time %d" % curren_time, TAG)
        key_to_delete = []

        # search in list, check time if too long, delete it
        for fid, value in self.tempfileList.items():
            if fid not in ignoreFids and value is not None:
                if (DEBUG): logD("fid %s time %d" % (fid,value[1]), TAG)
                if (curren_time - value[1]) >= self.DEFAULT_AUTO_CLEAR_TEMP_FILE_MS:
                    if (DEBUG): logD("add %s to del list" % fid, TAG)
                    key_to_delete.append(fid)
        
        # well, if found something, delete it
        numberDel = len(key_to_delete)
        if numberDel > 0:
            for fid in key_to_delete:
                if (DEBUG): logD("delete %s" % fid, TAG)
                self.removeTempFile(fid, False)       
        
        self.dumpTempList()
        log("deleted %d item" % numberDel, TAG)
        return numberDel

    # Build fid (file id), basing on original path + tag
    def getEncFileId(self, org_path, tag):
        if not self.is_ready:
            logE("storage manager not ready", TAG)
            return None
        
        # pathHash = hash.hashValString("%s%s" % (org_path, tag), HASH_ALGO)
        if (DEBUG): logD("getEncFileId %s" % org_path)
        if not os.path.exists(org_path):
            logE("file not found to gen fid", TAG)
            return None
        fid = hash.hashFile(org_path, HASH_ALGO)
        # logD("pathHash %s" % pathHash)
        # fid = common.encodeBase64(pathHash)
        # logD("fid %s" % fid)
        if (fid is not None):
            path = self.getEncFilePath(fid)
            if (DEBUG): logD("getEncFilePath %s" % path)
            if os.path.exists(path):
                # file already exist, generate new fid with current time
                curren_time = common.current_time("%Y/%m/%d %H:%M:%S.%f")
                if (DEBUG): logD("curren_time %s" % curren_time)
                pathHash2 = hash.hashValString("%s%s" % (fid, curren_time), HASH_ALGO)
                if (DEBUG): logD("pathHash 2 %s" % pathHash2)
                # fid = common.encodeBase64(pathHash2)
                fid = pathHash2.hex()
                if (fid is not None):
                    path = self.getEncFilePath(fid)
                    if os.path.exists(path):
                        # AGAIN !?!?!?!? stupid, return error ...
                        logE("Try twice, still duplicate, Faile to create id for file %s" % org_path)
                        return None
            # well done
            if (DEBUG): logD("tag %s, path %s --> id %s" % (tag, org_path, fid))
        else:
            logE("Faile to create id for file %s" % org_path)
            fid = None
        
        if (DEBUG): logD("generated fid %s" % fid)
        return fid

    # Build fid (file id), basing on buf
    def getEncFileIdFromBuf(self, buff):
        if not self.is_ready:
            logE("storage manager not ready", TAG)
            return None
        
        # pathHash = hash.hashValString("%s%s" % (org_path, tag), HASH_ALGO)
        if (DEBUG): logD("getEncFileIdFromBuf len %d" % len(buff))
        if buff is None or len(buff) == 0:
            logE("buff not found valid", TAG)
            return None
        randBuf = get_random_bytes(enc.AES_BLOCK_SIZE_BYTE) # try to make something different
        fid = hash.hashVal(buff + randBuf, HASH_ALGO).hex()
        # logD("pathHash %s" % pathHash)
        # fid = common.encodeBase64(pathHash)
        # logD("fid %s" % fid)
        if (fid is not None):
            # FIXME: duplicate code with getEncFileId, shold re-use?
            path = self.getEncFilePath(fid)
            if (DEBUG): logD("getEncFilePath %s" % path)
            if os.path.exists(path):
                # file already exist, generate new fid with current time
                curren_time = common.current_time("%Y/%m/%d %H:%M:%S.%f")
                if (DEBUG): logD("curren_time %s" % curren_time)
                pathHash2 = hash.hashValString("%s%s" % (fid, curren_time), HASH_ALGO)
                if (DEBUG): logD("pathHash 2 %s" % pathHash2)
                # fid = common.encodeBase64(pathHash2)
                fid = pathHash2.hex()
                if (fid is not None):
                    path = self.getEncFilePath(fid)
                    if os.path.exists(path):
                        # AGAIN !?!?!?!? stupid, return error ...
                        logE("Try twice, still duplicate, Faile to create id for buffer" )
                        return None
            # well done
            if (DEBUG): logD("fid %s" % (fid))
        else:
            logE("Faile to create id")
        
        if (DEBUG): logD("generated fid %s" % fid)
        return fid

    # Get full path to encrypted file, basing on fid
    def getEncFilePath(self, fid):
        global ENC_STORAGE_DIRECTORY
        return os.path.join(ENC_STORAGE_DIRECTORY, "%s.%s" % (fid, ENC_STORAGE_ENC_FNAME_EXT)) if fid is not None else None

    # Get full path of meta file of encrypted file, basing on fid
    def getEncFileMetaPath(self, fid):
        global ENC_STORAGE_DIRECTORY
        return os.path.join(ENC_STORAGE_DIRECTORY, "%s.%s" % (fid, ENC_STORAGE_META_FNAME_EXT)) if fid is not None else None

    # Get full path of meta file of storage management
    def getStorageMgrMetaPath(self):
        global ENC_STORAGE_DIRECTORY
        return os.path.join(ENC_STORAGE_DIRECTORY, ENC_STORAGE_META_FNAME)

    # Read meta data of encrypted file
    def readMetaFile(self, fid):
        if (DEBUG): logD("readMetaFile %s" % fid, TAG)
        if not self.is_ready:
            logE("storage manager not ready", TAG)
            return None
        
        if fid is None or len(fid) == 0:
            logE("invalid fid", TAG)
            return None

        meta_path = self.getEncFileMetaPath(fid)
        if (meta_path is None or not os.path.exists(meta_path)):
            logE("meta_path not found", TAG)
            return None

        # read meta file
        jdata = common.read_string_from_file(meta_path)
        if jdata is None or len(jdata) == 0:
            logE("read meta file failed for fid %s" % fid, TAG)
            return None
            
        meta = EncFileMeta()
        ret = meta.fromJson(jdata) # parse data
        if ret == common.ERR_NONE:
            # decrypt encrypted information
            if meta.fname is not None and len(meta.fname) > 0:
                if (DEBUG): logD("meta.fname %s" % meta.fname, TAG)
                meta.fname = enc.decryptFromBase64(None, bytes(meta.fname, 'utf-8'), self.key, self.meta.getIV())

            if meta.hash_plain is not None and len(meta.hash_plain) > 0:
                if (DEBUG): logD("meta.hash_plain %s" % meta.hash_plain, TAG)
                meta.hash_plain = enc.decryptFromBase64(None, bytes(meta.hash_plain, 'utf-8'), self.key, self.meta.getIV())

            if meta.tag is not None and len(meta.tag) > 0:
                if (DEBUG): logD("meta.tag %s" % meta.tag, TAG)
                meta.tag = enc.decryptFromBase64(None, bytes(meta.tag, 'utf-8'), self.key, self.meta.getIV())
            
            if meta.metaInfo is not None and len(meta.metaInfo) > 0:
                if (DEBUG): logD("meta.metaInfo %s" % meta.metaInfo, TAG)
                meta.metaInfo = enc.decryptFromBase64(None, bytes(meta.metaInfo, 'utf-8'), self.key, self.meta.getIV())

            if (DEBUG): logD("meta %s" % meta.toJson())
            return meta
        else:
            logE("read meta file failed for fid %s, parse failed %d" % (fid, ret), TAG)
            return None

    # read encrypted file, decrypt it and save to opath if it's specified, else temprary memory
    # return common.ERR_NONE on success, error on error
    # CALLER call getTmpFilePath(fid) to get path of file if not specify opath
    def readFile(self, fid, opath = None, override=True, ignoreCheck=False):
        log("readFile fid %s" % (fid), TAG)
        
        # check if storage is ready to use
        if not self.is_ready: 
            logE("storage manager not ready", TAG)
            return common.ERR_NOT_READY
        if fid is None:
            logE("invalid fid", TAG)
            return common.ERR_INVALID_ARGS

        # get encrypt file path
        enc_path = self.getEncFilePath(fid)
        if enc_path is None or not os.path.exists(enc_path):
            logE("not found file for fid %s" % fid)
            return common.ERR_INVALID_DATA

        if (DEBUG): logD("enc_path %s" % enc_path, TAG)
        
        # make temporary file if opath is not set
        if opath is None:
            opath = self.createTmpFile(fid)
            if opath is None:
                logE("Failed to make temp file for fid %s" % fid, TAG)
                return common.ERR_FAILED

        # lets read and decrypt, store to opath
        if (DEBUG): logD("let's read file, save to %s" % opath, TAG)
        ret = self.storage_impl.readFile(enc_path, opath)
        if ret != common.ERR_NONE:
            logE("not found file for fid %s" % fid)
            self.removeTempFile(fid)
            return None

        if (not ignoreCheck):
            # check with meta file
            meta = self.readMetaFile(fid)
            if meta is not None:
                hashRaw = hash.hashFile(opath, HASH_ALGO)

                # hash of raw is matched with expected one?
                if (DEBUG): logD("expect hash %s real hash %s" % (meta.hash_plain, hashRaw))
                if (hashRaw != meta.hash_plain):
                    self.removeTempFile(fid)
                    return common.ERR_NOT_MATCH
            else:
                self.removeTempFile(fid)
                logE("failed to decrypt, no meta data", TAG)
                return common.ERR_NOT_FOUND

        # all done
        if (DEBUG): logD("decrypt file for fid %s ok, opath %s" % (fid, opath), TAG)
        return common.ERR_NONE


    # build meta data for file to be enccrypted
    def buildMeta(self, path, tag, metaInfo=None):
        # check if storage is ready to use
        if not self.is_ready: 
            logE("storage manager not ready", TAG)
            return None

        if path is None or tag is None or not os.path.exists(path):
            logE("failed to build meta file, hash failed", TAG)
            return None
        
        if (DEBUG): logD("buildMeta path %s tag %s" % (path, tag), TAG)

        meta = EncFileMeta()
        meta.hash_algo = HASH_ALGO
        meta.encrypt_algo = ENCRYPT_ALGO
        hash_plain = hash.hashFile(path, HASH_ALGO)
        if hash_plain is None:
            logE("build meta file failed", TAG)
            return None
        
        # encrypt sensitive data
        meta.tag = enc.encrypt2Base64(None, bytes(tag, 'utf-8'), self.key, self.meta.getIV())
        fname = os.path.basename(path)
        meta.fname = enc.encrypt2Base64(None, bytes(fname, 'utf-8'), self.key, self.meta.getIV())
        meta.hash_plain = enc.encrypt2Base64(None, bytes(hash_plain, 'utf-8'), self.key, self.meta.getIV())

        if (metaInfo is not None and len(metaInfo) > 0):
            meta.metaInfo = enc.encrypt2Base64(None, bytes(metaInfo, 'utf-8'), self.key, self.meta.getIV())
        else:
            meta.metaInfo = ""
        
        meta.create_date = common.current_time("%Y/%m/%d %H:%M:%S")
        
        # well done
        return meta

    # build meta data for buffer to be enccrypted
    def buildBufMeta(self, buf, tag, metaInfo = None):
        # check if storage is ready to use
        if not self.is_ready: 
            logE("storage manager not ready", TAG)
            return None

        if buf is None or tag is None:
            logE("failed to build meta file", TAG)
            return None
        
        if (DEBUG): logD("buildBufMeta tag %s" % (tag), TAG)

        meta = EncFileMeta()
        meta.hash_algo = HASH_ALGO
        meta.encrypt_algo = ENCRYPT_ALGO
        hash_plain = hash.hashVal(buf, HASH_ALGO, toHexString=True)
        if hash_plain is None:
            logE("build meta file failed for buf, hash failed", TAG)
            return None
        
        meta.tag = enc.encrypt2Base64(None, bytes(tag, 'utf-8'), self.key, self.meta.getIV())
        # meta.fname = enc.encrypt2Base64(None, bytes(fname, 'utf-8'), self.key, self.meta.getIV())
        meta.hash_plain = enc.encrypt2Base64(None, bytes(hash_plain, 'utf-8'), self.key, self.meta.getIV())
        
        if (metaInfo is not None and len(metaInfo) > 0):
            meta.metaInfo = enc.encrypt2Base64(None, bytes(metaInfo, 'utf-8'), self.key, self.meta.getIV())
        else:
            meta.metaInfo = ""

        meta.create_date = common.current_time("%Y/%m/%d %H:%M:%S")
        # well done
        return meta

    # encrypt file and store to storage manager's location
    # return ERR_NONE and fid on success, error code on error
    def writeFile(self, path, tag, metaInfo=None, force=False):
        # check if storage is ready to use
        if not self.is_ready: 
            logE("storage manager not ready", TAG)
            return [common.ERR_NOT_READY, None]

        meta = self.buildMeta(path, tag, metaInfo)
        if meta is None:
            logE("build meta failed", TAG)
            return [common.ERR_FAILED, None]
        
        if (DEBUG): logD("Write file path %s tag %s" % (path, tag))
        
        # build fid basing on file path and tag
        fid = self.getEncFileId(path, tag)
        if (DEBUG): logD("fid %s" % fid)

        enc_path = self.getEncFilePath(fid)
        meta_path = self.getEncFileMetaPath(fid)
        if (DEBUG): logD("enc_path %s meta_path %s" % (enc_path, meta_path))
        if (enc_path is not None) and (meta_path is not None):
            if os.path.exists(enc_path):
                if not force:
                    logE("Filed exist! should force?")
                    return [common.ERR_EXISTED, None]
                else:
                    if (DEBUG): logD("remove enc_path %s" % enc_path)
                    os.remove(enc_path)
            
            try:
                # IV will be generated randomly by file encryption engine, and embedde inside cipher test
                # we don't need to generate random iv here
                # will comback if engine not support to generate random iv
                ret = self.storage_impl.writeFile(path, enc_path)
                if ret == common.ERR_NONE:
                    # write meta file
                    metajson = meta.toJson()
                    if metajson is not None:
                        if (DEBUG): logD("metajson %s" % metajson)
                        ret = common.write_string_to_file(meta_path, metajson, force)
                        if ret:
                            # WELL DONE
                            if (DEBUG): logD("Encrdypt and save %s to fid %s" % (path, fid))
                            return [common.ERR_NONE, fid]
                        else:
                            logE("Failed to store meta file", TAG)
                            return [common.ERR_FAILED, None]

                    else:
                        logE("Failed to build meta file", TAG)
                        return [common.ERR_FAILED, None]
                    
                else:
                    logE("Failed to encrypt file, ret %d" % ret, TAG)
                    return [ret, None]
            except:
                traceback.print_exc()
                return [common.ERR_EXCEPTION, None]
        else:
            return [common.ERR_FAILED, None]


    # encrypt file and store to opath
    # return ERR_NONE and path to meta file, error code on error
    def writeBuf2File(self, buf, ofile=None, metaInfo = None, tag=""):
        # check if storage is ready to use
        if not self.is_ready: 
            logE("storage manager not ready", TAG)
            return [common.ERR_NOT_READY, None, None]
        
        if (buf is None) or len(buf) == 0:
            logE("invalid arg", TAG)
            return [common.ERR_INVALID_ARGS, None, None]
        
        fid = None

        meta_path = None
        if ofile is None or len(ofile) == 0:
            fid = self.getEncFileIdFromBuf(buf)
            if (fid is not None):
                ofile = self.getEncFilePath(fid)
                meta_path = self.getEncFileMetaPath(fid)
            else:
                logE("Faild to generate fid", TAG)
                return [common.ERR_FAILED, None, None]
        else:
            meta_path = "%s.%s" % (ofile, ENC_STORAGE_META_FNAME_EXT)

        if ofile is None or len(ofile) == 0 or meta_path is None or len(meta_path) == 0:
            logE("No output path", TAG)
            return [common.ERR_FAILED, None, None]

        if (DEBUG): logD("encrypt buf and store to %s" % (ofile))

        if os.path.exists(ofile):
            logE("file already exist", TAG)
            return [common.ERR_EXISTED, None, None]


        if (DEBUG): logD("meta_path %s" % meta_path)

        meta = self.buildBufMeta(buf, tag, metaInfo)
        if meta is not None:
            ret = self.storage_impl.writeBuf2File(buf, ofile)
            if (DEBUG): logD("writeBuf2File %d" % ret)
            if ret == common.ERR_NONE:
                metajson = meta.toJson()
                if metajson is not None:
                    if (DEBUG): logD("metajson %s" % metajson)
                    ret = common.write_string_to_file(meta_path, metajson)
                    if (DEBUG): logD("write_string_to_file %d" % ret)
                    if (ret):
                        return [common.ERR_NONE, metajson, fid if fid is not None else ofile]
                    else:
                        return [common.ERR_FAILED, None, None]
                else:
                    return [common.ERR_FAILED, None, None]
            else:
                return [ret, None, None]
        else:
            return [common.ERR_FAILED, None, None]
    

    def changePwd(self, oldPass, newPass):
        # TODO: 
        # decrypt with old pass and encrypt with new pass, put to new folder, and swith to new folder (A/B partition)
        return common.ERR_NONE
    
    #
    # Delete file fid
    # forceDelete: set True if actually delete file, else it's just move to delete folder
    # WARNING: key is sensitive/important data, so be care when force delete
    # return ERR_NONE on success
    def delete(self, fid, forceDelete=False):
        if (DEBUG): logD("Delete %s" % fid, TAG)
        # make folder which store deleted files
        ret = common.ERR_NONE
        global ENC_STORAGE_DELETE_DIR
        if not os.path.exists(ENC_STORAGE_DELETE_DIR):
            if (DEBUG): logD("Create delete dir %s" % ENC_STORAGE_DELETE_DIR, TAG)
            os.makedirs(ENC_STORAGE_DELETE_DIR)

        for listener in self.listeners:
            if listener is not None:
                if (DEBUG): logD("call onKeyDeleted")
                ret = listener.onFileDeleted(fid)
                if ret != common.ERR_NONE:
                    msg = "%s not allowed to delete by %s" % (key_id, listener.getName())
                    logE(msg, TAG)
                    break
        if ret != common.ERR_NONE:
            return ret
        enc_path = self.getEncFilePath(fid)
        meta_path = self.getEncFileMetaPath(fid)

        del_time = common.current_time("%Y%m%d_%H%M%S%f")
        if (os.path.exists(enc_path)):
            del_enc_path = os.path.join(ENC_STORAGE_DELETE_DIR, "%s_del_%s.%s" % (fid, del_time, ENC_STORAGE_ENC_FNAME_EXT))
            if (DEBUG): logD("move %s to %s" % (enc_path, del_enc_path), TAG)
            if forceDelete:
                os.remove(enc_path)
            else:
                shutil.move(enc_path, del_enc_path)
        
        if (os.path.exists(meta_path)):
            del_meta_path= os.path.join(ENC_STORAGE_DELETE_DIR, "%s_del_%s.%s" % (fid, del_time, ENC_STORAGE_META_FNAME_EXT))
            if (DEBUG): logD("move %s to %s" % (meta_path, del_meta_path), TAG)
            if forceDelete:
                os.remove(meta_path)
            else:
                shutil.move(meta_path, del_meta_path)

        # delete temp file if any
        self.removeTempFile(fid)
        return common.ERR_NONE



###########################################################################################
###########################################################################################

mgr = None

# get storage manage instance
def storageMgr():
    global mgr
    if mgr is None:
        mgr = StorageMgr(StorageAesCrypImpl())
    return mgr

# init storage management
def init_storage_management(app = None):
    log("init_storage_management", TAG, True)
    
    ret = common.ERR_NONE

    global ENC_STORAGE_DIRECTORY
    global ENC_STORAGE_DELETE_DIR
    ENC_STORAGE_DIRECTORY = os.path.join(getRootDataDir(), ENC_STORAGE_DIRECTORY_NAME)
    ENC_STORAGE_DELETE_DIR = os.path.join(ENC_STORAGE_DIRECTORY, ENC_STORAGE_DELETE_DIR_FNAME)

    # make storage
    if (not os.path.exists(ENC_STORAGE_DIRECTORY)):
        log("Make storage %s" % ENC_STORAGE_DIRECTORY, TAG)
        os.makedirs(ENC_STORAGE_DIRECTORY)
    else:
        log("Storage %s ready" % ENC_STORAGE_DIRECTORY, TAG)

    global mgr
    mgr = StorageMgr(StorageAesCrypImpl())
    if ret == common.ERR_NONE:
        server.monitor.system_report.sysReport().setStatus(
            server.monitor.system_report.MODULE_NAME_STORAGE,
            server.monitor.system_report.MODULE_STATUS_INIT,
            "storage inited"
            )
    else:
        server.monitor.system_report.sysReport().setStatus(
            server.monitor.system_report.MODULE_NAME_STORAGE,
            server.monitor.system_report.MODULE_STATUS_FAILED,
            "storage init failed"
            )

    return ret

# init storage management
def setup_storage_management(app = None, key = None, auto_set_pass=False):
    log("setup_storage_management", TAG, True)
    
    ret = common.ERR_NONE

    if auto_set_pass or storageMgr().isPasswordSet():
        ret = storageMgr().setup(key)
    else:
        logE("not set password yet", TAG)
        ret = common.ERR_NOT_READY

    log("Init storage result %d" % ret)

    if ret == common.ERR_NONE:
        log("Register storage to backup manager")
        from server.backup.backup_mgr import backupMgr
        backupMgr().registerBackup(storageMgr())

    if ret == common.ERR_NONE:
        server.monitor.system_report.sysReport().setStatus(
            server.monitor.system_report.MODULE_NAME_STORAGE,
            server.monitor.system_report.MODULE_STATUS_READY,
            "storage ready"
            )
    else:
        server.monitor.system_report.sysReport().setStatus(
            server.monitor.system_report.MODULE_NAME_STORAGE,
            server.monitor.system_report.MODULE_STATUS_FAILED,
            "storage setup failed"
            )
            
    return ret

def exit_storage_management(app = None):
    log("exit_storage_management", TAG, True)
    server.monitor.system_report.sysReport().setStatus(
            server.monitor.system_report.MODULE_NAME_STORAGE,
            server.monitor.system_report.MODULE_STATUS_NONE,
            "storage is deninted"
            )
    storageMgr().exit()