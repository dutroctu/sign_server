#!/usr/bin/env python
#

import os
import sys
from server.storage import IStorage
import pyAesCrypt
import traceback
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import hashlib

from server.applog import log
from server.applog import logE
from server.applog import logD
from server import common as common
from server import hash as hash
import io
from server.app import DEBUG
# encryption/decryption buffer size - 1K
# must be a multiple of AES block size (16)
ENCRYPT_BUF_SIZE = 1 * 1024

TAG = "StorageAesCrypImpl"
import tempfile
#
# File encryption using pyaescrypt libraries
# 
# Check follopwing website:
# https://pypi.org/project/pyAesCrypt/
# https://github.com/marcobellaccini/pyAesCrypt/blob/master/pyAesCrypt/crypto.py
# https://www.aescrypt.com/aes_file_format.html
# https://www.aescrypt.com/pyaescrypt.html
class StorageAesCrypImpl(IStorage):

    key = None
    def __init__(self):
        self.key = None

    # seup key, return ERR_NONE on success, error code otherwise
    def setKey(self, pwd, salt):
        # calculate
        try:
            key = hash.kdfFromString(pwd, salt)
            if (key != None):
                # logD("base64 %s" % base64.urlsafe_b64encode(key))
                self.key = key
                log("setup key ok", TAG)
                return common.ERR_NONE
            else:
                logE("failed to setup key, no data", TAG)
                return common.ERR_NO_DATA
        except:
            traceback.print_exc()
            logE("failed to setup key", TAG)
            return common.ERR_EXCEPTION


    # read and decrypt file, save to ofile.
    # return ofile path on success, or None otherwise. Exception may be raised in case of error
    # caller must make sure ofile not exist and folder to ofile already ready
    def readFile(self, ifile, ofile):
        if self.key is not None:
            if ((ifile is not None and len(ifile) > 0 and os.path.exists(ifile)) 
                and (ofile is not None and len(ofile) > 0)):
                if (DEBUG): logD("readFile i=%s o=%s" % (ifile, ofile), TAG)
                try:
                    pyAesCrypt.decryptFile(ifile, ofile, self.key.hex(), ENCRYPT_BUF_SIZE)
                    if (DEBUG): logD("decrypt file ok")
                    return common.ERR_NONE
                except:
                    traceback.print_exc()
                    logE("failed decrypt file %s" % ifile, TAG)
                    return common.ERR_EXCEPTION
            else:
                logE("failed to decrypt file, invalid input", TAG)
                return common.ERR_INVALID_ARGS
        else:
            logE("failed to decrypt file, no key", TAG)
            return common.ERR_NOT_READY

    # encrypt ifle and store to ofile
    # return ERR_NONE on success, or error code otherwise. Exception may be raised in case of error
    # caller must make sure ofile not exist and folder to ofile already ready
    def writeFile(self, ifile, ofile):
        if self.key is not None:
            if ((ifile is not None and len(ifile) > 0 and os.path.exists(ifile)) 
                and (ofile is not None and len(ofile) > 0)):
                if not os.path.exists(ofile): # ofile exist?
                    if (DEBUG): logD("writeFile i=%s o=%s" % (ifile, ofile), TAG)
                    try:
                        pyAesCrypt.encryptFile(ifile, ofile, self.key.hex(), ENCRYPT_BUF_SIZE)
                        if (DEBUG): logD("encrypt file ok")
                        return common.ERR_NONE
                    except:
                        traceback.print_exc()
                        logE("failed encrypt file %s" % ifile, TAG)
                        return common.ERR_EXCEPTION
                else:
                    logE("failed to encrypt file, ofile already exist input", TAG)
                    return common.ERR_EXISTED
            else:
                logE("failed to encrypt file, invalid input", TAG)
                return common.ERR_INVALID_ARGS
        else:
            logE("failed to encrypt file, no key", TAG)
            return common.ERR_NOT_READY
        
        return 

    # encrypt buffer and write to ofile
    # return ERR_NONE on success, or error code otherwise. Exception may be raised in case of error
    def writeBuf2File(self, buf, ofile):
        if self.key is not None:
            if ((buf is not None and len(buf) > 0) 
                and (ofile is not None and len(ofile) > 0)):
                if not os.path.exists(ofile):
                    if (DEBUG): logD("writeBuf2File o=%s" % (ofile), TAG)
                    try:
                        # input plaintext binary stream
                        fIn = io.BytesIO(buf)
                        with open(ofile, "wb") as fCiph:
                            pyAesCrypt.encryptStream(fIn, fCiph, self.key.hex(), ENCRYPT_BUF_SIZE)
                        if (DEBUG): logD("writeBuf2File file ok")
                        return common.ERR_NONE
                    except:
                        traceback.print_exc()
                        logE("failed writeBuf2File file", TAG)
                        return common.ERR_EXCEPTION
                else:
                    logE("failed to writeBuf2File file, ofile already exist input", TAG)
                    return common.ERR_EXISTED
            else:
                logE("failed to writeBuf2File file, invalid input", TAG)
                return common.ERR_INVALID_ARGS
        else:
            logE("failed to writeBuf2File file, no key", TAG)
            return common.ERR_NOT_READY



    def getName(self):
        return "pyAesCrypt"

