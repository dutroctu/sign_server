#!/usr/bin/env python
#
#  ENTRY FOR SERVER
#

import sys
import os
import time
import hashlib
import shutil
from server import applog as applog 
import traceback
import uuid
import random
from datetime import datetime
from server.applog import logE
from server.applog import logD
from server.applog import log
from server import common as common 
from server.common import BUF_SIZE
from server.app import DEBUG
ALGO_MD5="md5"
ALGO_SHA1="sha1"
ALGO_SHA256="sha256"
ALGO_AES_256_CBC = "aes-cbc-256"

DEFAULT_ITERATION_LOOP = 100000

# calculate md5 of a file
# return hex string on success, None on error
def md5file(path):
    if os.path.exists(path):
        try:
            md5 = hashlib.md5()
            with open(path, 'rb') as f:
                while True:
                    data = f.read(common.BUF_SIZE)
                    if not data:
                        break
                    md5.update(data)
            return md5.hexdigest()
        except :
            traceback.print_exc()
            if (DEBUG): logD("md5 % failed"  % path)
            return None
    else:
        return None


# calculate sha1 of a file
# return hex string on success, None on error
def sha1file(path):
    if os.path.exists(path):
        try:
            sha1 = hashlib.sha1()
            with open(path, 'rb') as f:
                while True:
                    data = f.read(BUF_SIZE)
                    if not data:
                        break
                    sha1.update(data)
            return sha1.hexdigest()
        except :
            traceback.print_exc()
            if (DEBUG): logD("sha1 % failed"  % path)
            return None
    else:
        return None

def sha256file(path):
    if os.path.exists(path):
        try:
            sha256 = hashlib.sha256()
            with open(path, 'rb') as f:
                while True:
                    data = f.read(BUF_SIZE)
                    if not data:
                        break
                    sha256.update(data)
            return sha256.hexdigest()
        except :
            traceback.print_exc()
            if (DEBUG): logD("sha256 % failed"  % path)
            return None
    else:
        return None



HASH_FILE_ALG = {
    ALGO_MD5:md5file,
    ALGO_SHA1:sha1file,
    ALGO_SHA256:sha256file,
}

def hashFile(path, algo):
    func = HASH_FILE_ALG[algo] if algo in HASH_FILE_ALG.keys() else None
    if (func is not None):
        return func(path)
    else:
        logE("Algo '%s' not support" % algo)
        return None




# do sha1 buffer, return hex string
def sha1(value):
    try:
        sha1 = hashlib.sha1()
        sha1.update(value)
        return sha1.hexdigest()
    except :
        traceback.print_exc()
        if (DEBUG): logD("sha1 % failed"  % value)
        return None


HASH_VAL_ALG = {
    ALGO_MD5:hashlib.md5,
    ALGO_SHA1:hashlib.sha1,
    ALGO_SHA256:hashlib.sha256,
}

def hashVal(value, algo, toHexString=False):
    func = HASH_VAL_ALG[algo] if algo in HASH_VAL_ALG.keys() else None
    if (func is not None):
        try:
            hashfunc = func()
            hashfunc.update(value)
            if toHexString:
                return hashfunc.hexdigest()
            else:
                return hashfunc.digest()
        except :
            traceback.print_exc()
            if (DEBUG): logD("sha1 % failed"  % value)
            return None
    else:
        logE("Algo '%s' not support" % algo)
        return None

def hashValString(value, algo):
    if (DEBUG): logD("hashValString %s algo %s" % (value, algo))
    return hashVal(bytes(value, 'utf-8'), algo)


def kdfFromString(key, salf, loop=DEFAULT_ITERATION_LOOP):
    # WARNING: It's used to make key for encryption. ANY CHANGES, MUST MAKE SURE BACKWARD COMPATIBLE
     
    # use Fernet
    # from cryptography.hazmat.backends import default_backend
    # from cryptography.hazmat.primitives import hashes
    # from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    # kdf = PBKDF2HMAC(
    #     algorithm=hashes.SHA256(),
    #     length=32,
    #     salt=bytes(salt, 'utf-8'),
    #     iterations=100000,
    #     backend=default_backend()
    # )
    # key = kdf.derive(bytes(pwd, 'utf-8'))  # Can only use kdf once
    dk = hashlib.pbkdf2_hmac('sha256', bytes(key, 'utf-8'), bytes(salf, 'utf-8'), loop)
    return dk