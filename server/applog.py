#!/usr/bin/env python
import sys
import os
import traceback
import shlex
import datetime
from os import path
from os import listdir
from os.path import isfile, join

from sys import platform as _platform
from os.path import isfile, join
import codecs
import subprocess
import tempfile

import requests
import getpass
import struct
#import pexpect
import zipfile
import glob
import shutil
import time
from datetime import datetime
import threading

logFilePath = None
logFile = None
LOG_TO_FILE = False
folder = None
runtimelog = None

TAG_RUNTIME_LOG = "runtimelog"
TAG_INCIDENT_LOG = "incidentreport"

TAG = "applog"
LOG_DIR = ".log"
class LogItem:
    id = None
    fpath = None
    desc = None
    last_update_time = None
    size = 0
    def toString(self):
        val = ""
        val += "id: %s;\n" % self.id
        val += "fpath: %s;\n" % self.fpath
        val += "last_update_time: %s;\n" % self.last_update_time
        val += "size: %d;\n" % self.size
        return val


def debug():
    from server.app import is_debug
    return is_debug()

def log_msg(tag, msg):
    return "[%d.%d][%s] %s: %s" % (os.getpid(),threading.get_ident(), datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ'), tag, msg)

def saveToLogFile(msg):
    """
    Save to log file
    """
    global logFilePath
    global logFile
    global folder
    try:
        # TODO: SHOULD make other thread to write log, to avoid performance issue when log file become huge....

        # anhnh57 2022/03/11: change log filename to month-base, to reduce the numbere of log
        # __path = os.path.join(folder, "log_%s" % datetime.now().strftime('%Y_%m_%d'))
        __path = os.path.join(folder, "log_%s" % datetime.now().strftime('%Y_%m'))
        # TODO: auto delete old log

        if (debug()): logD("__path %s" %__path, TAG)
        if (__path != logFilePath):
            logFilePath = __path
            if logFile is not None:
                logFile.close()
                logFile = None
        
        if logFile is None:
            if os.path.exists(__path):
                logFile = open(logFilePath,"a+")
            else:
                logFile = open(logFilePath,"w")
        if logFile is not None:
            # logFile = open(logFilePath,"a+")
            logFile.write("%s\n" % str(msg))
            logFile.flush()
            # logFile.close()
    except:
        traceback.print_exc()
        return False
        
    return True

def logE(msg, tag=None, toFile=LOG_TO_FILE):
    __msg = log_msg("E" if tag is None else "E %s" % tag, msg)
    print(__msg)
    if (toFile) :
        saveToLogFile(__msg)

def log(msg, tag=None, toFile=LOG_TO_FILE):
    __msg = log_msg("I" if tag is None else "I %s" % tag, msg)
    print(__msg)
    if (toFile) :
        saveToLogFile(__msg)

def logD(msg, tag=None, toFile=LOG_TO_FILE):
    if (debug()):
        __msg = log_msg("D" if tag is None else "D %s" % tag, msg)
        print(__msg, flush=True)
        if (toFile) :
            saveToLogFile(__msg)

def printBytes(msg, data, tag=None, isdebug=True, endmsg = None):
    if (data is not None and len(data) > 0):
        msg += "(%d) 0x" % len(data)
        for i in data:
            msg += "%02x" % i
    else:
        msg += "no data"
    if endmsg is not None:
        msg += endmsg
    if isdebug:
        logD(msg, tag)
    else:
        log(msg, tag)

def init_log(dir, runlog = None):
    # global logFilePath
    global logFilePath
    global folder
    global runtimelog
    folder = os.path.join(dir, LOG_DIR)

    if not os.path.exists(folder):
        os.makedirs(folder)
    
    runtimelog = runlog
    # logFilePath = os.path.join(folder, "log_%d" % current_milli_time())
    logFilePath = os.path.join(folder, "log_%s" % datetime.now().strftime('%Y_%m_%d'))
    log ("LOG file path %s" % logFilePath)

def getRunningLogFile():
    global runtimelog
    global logFilePath
    return {
        "runtime":runtimelog,
        "logfile":logFilePath
    }

def getLogList():
    loglist = {}
    global runtimelog
    global logFilePath
    global folder
    from server import common
    if (debug()): logD("getLogList", TAG)
    if runtimelog is not None and os.path.exists(runtimelog):
        if (debug()): logD("add runtimelog %s" % runtimelog, TAG)
        __logitem = LogItem()
        __logitem.id = TAG_RUNTIME_LOG
        __logitem.fpath = runtimelog
        __logitem.desc = "Run time log (ACTIVE)"
        __logitem.last_update_time = time.ctime(os.path.getmtime(runtimelog))
        __logitem.size = os.path.getsize(runtimelog)
        loglist[__logitem.id] = __logitem

    from server.monitor.system_report import sysReport
    incident_report_fpath = sysReport().getIncidentReportFpath()

    if incident_report_fpath is not None:
        if (debug()): logD("add incident_report_fpath %s" % incident_report_fpath, TAG)
        __logitem = LogItem()
        __logitem.id = TAG_INCIDENT_LOG
        __logitem.fpath = incident_report_fpath
        __logitem.desc = "Incident report log (ACTIVE)"
        __logitem.last_update_time = time.ctime(os.path.getmtime(incident_report_fpath))
        __logitem.size = os.path.getsize(incident_report_fpath)
        loglist[__logitem.id] = __logitem

    # Dump queue file path
    from server.monitor.system_monitor import sysMon
    from server.monitor.system_monitor import DUMP_QUEUE_LOG_FNAME
    mon_fpath = sysMon().getMonDumpReqQueueFPath()
    if mon_fpath is not None and os.path.exists(mon_fpath):
        if (debug()): logD("add Dump queue File Path %s" % mon_fpath, TAG)
        __logitem = LogItem()
        __logitem.id = DUMP_QUEUE_LOG_FNAME
        __logitem.fpath = mon_fpath
        __logitem.desc = DUMP_QUEUE_LOG_FNAME
        __logitem.last_update_time = time.ctime(os.path.getmtime(mon_fpath))
        __logitem.size = os.path.getsize(mon_fpath)
        loglist[__logitem.id] = __logitem

    if folder is not None and os.path.exists(folder):
        for fname in os.listdir(folder):
            if (debug()): logD("add log %s" % fname, TAG)
            fpath = os.path.join(folder, fname)
            if os.path.isfile(fpath):
                __logitem = LogItem()
                __logitem.id = fname
                __logitem.fpath = fpath
                __logitem.desc = "App log - %s %s" % (fname, "(ACTIVE)" if fpath == logFilePath else "")
                __logitem.last_update_time = time.ctime(os.path.getmtime(fpath))
                __logitem.size = os.path.getsize(fpath)
                loglist[__logitem.id] = __logitem
    

    if (debug()): logD("loglist %s" % str(loglist.keys()), TAG)
    return loglist

DEFAULT_TAG = "signer"
class Log:
    tag = DEFAULT_TAG
    def __init__(self, tag=DEFAULT_TAG):
        self.tag = tag

    def d(self, msg, toFile=LOG_TO_FILE):
        logD(msg, self.tag, toFile)

    def i(self, msg, toFile=LOG_TO_FILE):
        log(msg, self.tag, toFile)

    def e(self, msg, toFile=LOG_TO_FILE):
        logE(msg, self.tag, toFile)

    def dumpBytes(self, msg, data):
        if debug():
            self.printBytes(msg, data, True)

    def printBytes(self, msg, data, isdebug=False, endmsg = None):
        if (data is not None and len(data) > 0):
            msg += "(%d) 0x" % len(data)
            for i in data:
                msg += "%02x" % i
        else:
            msg += "no data"
        if endmsg is not None:
            msg += endmsg
        if isdebug:
            self.d(msg)
        else:
            self.i(msg)