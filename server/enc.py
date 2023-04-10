#!/usr/bin/env python
#
#  ENTRY FOR SERVER
#

import sys
import os
import time
import hashlib
import shutil
import traceback
import uuid
import random
from datetime import datetime
from server.applog import logE
from server.applog import logD
from server.applog import log
from server import common as common 
import base64 
import hashlib 
from server.common import BUF_SIZE
from server.app import getRootToolDir
import tempfile
from server import app
from server.app import DEBUG

TAG = "enc"

SSH_RSA_SCRIPT_FNAME="ssh_rsa_encrypt.sh"
SSH_RSA_SCRIPT = os.path.join(getRootToolDir(), SSH_RSA_SCRIPT_FNAME)

COMMAND_TIMEOUT_SECOND = 30
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

ALGO_AES_256_CBC = "aes-cbc-256"

AES_BLOCK_SIZE_BIT = 128
AES_BLOCK_SIZE_BYTE = int(AES_BLOCK_SIZE_BIT/8)

DATA_TYPE_ANY = 0
DATA_TYPE_HEX = 1
DATA_TYPE_BASE64 = 1
DATA_TYPE_STRING = 2

def byte2Data(data, type):
    switcher = {
        DATA_TYPE_HEX:      lambda x: x.hex(),
        DATA_TYPE_BASE64:   lambda x: base64.urlsafe_b64encode(x).decode(),
        DATA_TYPE_STRING:   lambda x: x.decode('utf-8'),
        }
    func = switcher.get(type, lambda data: data)
    return func(data)



def encrypt2Base64(alg, data, key, iv):
    m = hashlib.sha256()
    m.update(iv)
    realiv = m.digest()

    if (DEBUG): logD("encrypt2Base64 %s " % data, TAG)
    cipher = AES.new(key, AES.MODE_CBC,realiv[:16])
    ct = pad(data, AES.block_size)
    ct_bytes = cipher.encrypt(ct)
    return byte2Data(ct_bytes, DATA_TYPE_BASE64)


def decryptFromBase64(alg, data, key, iv):
    if (DEBUG): logD("decryptFromBase64 %s " % data, TAG)
    m = hashlib.sha256()
    m.update(iv)
    realiv = m.digest()

    byte_data = base64.urlsafe_b64decode(data)
    cipher = AES.new(key, AES.MODE_CBC,realiv[:16])
    dt = cipher.decrypt(byte_data)
    if (DEBUG): logD("result %s" % str(dt), TAG)
    pt = unpad(dt, AES.block_size)
    return pt.decode('utf-8')

PRIV_KEY_TAG = "priv"
PUB_KEY_TAG = "pub"

COMMAND_TIMEOUT_SECOND=30
# return none on error, else dict with key and path
def generateRsaKey(pwd, keydir, privName, pubName, keysize=2048):
    if (DEBUG): logD("generateRsaKey to %s, keysize %d" % (keydir, keysize), TAG)
    keys = {}
    if not os.path.exists(keydir):
        logE("%s not exist" % keydir, TAG)
        return None
    priv = os.path.join(keydir, privName)
    pub = os.path.join(keydir, pubName)
    command = "openssl genrsa %d > %s" % (keysize, priv)
    ret = common.ERR_NONE
    try:
        import subprocess
        child = subprocess.run(command, shell=True, timeout = COMMAND_TIMEOUT_SECOND if COMMAND_TIMEOUT_SECOND > 0 else None)
        ret = child.returncode
    except:
        traceback.print_exc()
        msg = "Exception"
        ret = common.ERR_EXCEPTION
    
    if ret == common.ERR_NONE and os.path.exists(priv):
        command = "openssl rsa -pubout < %s > %s " % (priv, pub)
        try:
            import subprocess
            child = subprocess.run(command, shell=True, timeout = COMMAND_TIMEOUT_SECOND if COMMAND_TIMEOUT_SECOND > 0 else None)
            ret = child.returncode
        except:
            traceback.print_exc()
            msg = "Exception"
            ret = common.ERR_EXCEPTION

        if ret == common.ERR_NONE and os.path.exists(priv) and os.path.exists(pub):
            if (DEBUG): logD("Save priv %s " % priv, TAG)
            keys[privName] = priv
            keys[pubName] = pub
        else:
            keys = None
            logE("Extract pubout failed", TAG)
    else:
        keys = None
        logE("gen rsa failed", TAG)
    return keys


def ssh_rsa_verify_id_rsa_file(rsafile):
    if (DEBUG): logD("ssh_rsa_verify_id_rsa_file rsa %s" % (rsafile), TAG)

    command = "%s verify --id_rsa='%s'" % (SSH_RSA_SCRIPT, rsafile)
    ret = common.ERR_NONE
    try:
        import subprocess
        child = subprocess.run(command, shell=True, timeout = COMMAND_TIMEOUT_SECOND if COMMAND_TIMEOUT_SECOND > 0 else None)
        ret = child.returncode
        if child.returncode == 0:
            ret = common.ERR_NONE
        else:
            ret = common.ERR_FAILED
    except:
        traceback.print_exc()
        msg = "Exception"
        ret = common.ERR_EXCEPTION
    
    return ret


def ssh_rsa_verify_id_rsa(rsa):
    if (DEBUG): logD("ssh_rsa_verify_id_rsa rsa %s" % (rsa), TAG)

    f = tempfile.NamedTemporaryFile()
    common.write_string_to_file(f.name, rsa)
    ret = ssh_rsa_verify_id_rsa_file(f.name)
    f.close()
    return ret


def ssh_rsa_encrypt_id_rsa_file(rsafile, finput, foutputdir, outname=None):
    if (DEBUG): logD("ssh_rsa_encrypt_id_rsa_file rsa %s finput %s foutputdir %s" % (rsafile, finput, foutputdir), TAG)

    command = "%s encrypt %s --id_rsa='%s' --input='%s' --output='%s' --outname='%s'" % (
        SSH_RSA_SCRIPT, 
        "-v" if app.DEBUG else "",
        rsafile, 
        finput, 
        foutputdir,
        outname if outname is not None else ""
        )
    ret = common.ERR_NONE
    try:
        import subprocess
        child = subprocess.run(command, shell=True, timeout = COMMAND_TIMEOUT_SECOND if COMMAND_TIMEOUT_SECOND > 0 else None)
        ret = child.returncode
        if child.returncode == 0:
            ret = common.ERR_NONE
        else:
            ret = common.ERR_FAILED
    except:
        traceback.print_exc()
        msg = "Exception"
        ret = common.ERR_EXCEPTION
    
    return ret