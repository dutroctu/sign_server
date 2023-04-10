#!/usr/bin/env python
#
#  KEY MANAGEMENT
#


from flask import redirect, url_for
from server.app import DEBUG

import os
from server.applog import log
from server.applog import logE
from server.applog import logD
from server import common as common
from server.app import DEBUG
from server.app import getRootDataDir

import traceback

TAG = "SystemReport"


MODULE_STATUS_FAILED = -1
MODULE_STATUS_NONE = 0
MODULE_STATUS_INIT = 1
MODULE_STATUS_READY = 2

MODULE_STATUS_TO_NAME = {
    MODULE_STATUS_FAILED:"MODULE_STATUS_FAILED",
    MODULE_STATUS_NONE:"MODULE_STATUS_NONE",
    MODULE_STATUS_INIT:"MODULE_STATUS_INIT",
    MODULE_STATUS_READY:"MODULE_STATUS_READY",
}

MODULE_NAME_DB = "database"
MODULE_NAME_STORAGE = "storage"

#folder to store key file
SYSTEM_REPORT = ".report"
INCIDENT_REPORT_FNAME = "incident.csv"

SYSTEM_REPORT_DIRECTORY = os.path.join(getRootDataDir(), SYSTEM_REPORT)
INCIDENT_REPORT_FILE_PATH = os.path.join(SYSTEM_REPORT_DIRECTORY, INCIDENT_REPORT_FNAME)

INCIDENT_SEVERITY_LOW = 0 # informative
INCIDENT_SEVERITY_MIDDLE = 1 # Need to look at it 
INCIDENT_SEVERITY_CRITICAL = 2 # need to take action now!!!!

class SystemReport(object):
    module_status = {
        MODULE_NAME_DB:[MODULE_STATUS_NONE, "not init"],
        MODULE_NAME_STORAGE:[MODULE_STATUS_NONE, "not init"],
    }

    def setStatus(self, module, status, msg=None):
        if (DEBUG): logD("setStatus, module %s status %d msg %s" % (module, status, msg), TAG)
        if status in MODULE_STATUS_TO_NAME:
            self.module_status[module] = [status, msg]
            ret = common.ERR_NONE
        else:
            ret = common.ERR_INVALID_ARGS
        return ret

    def checkStatus(self, module=None, status=MODULE_STATUS_READY):
        if (DEBUG): logD("checkStatus, module %s status %d" % (module, status), TAG)
        ok = True
        if module is None:
            for key, value in self.module_status.items():
                if value[0] != status:
                    ok = False
                    break
        else:
            if module in self.module_status and self.module_status[module][0] == status:
                ok = True
            else:
                ok = False
        if (DEBUG): logD("Status: %d" % ok, TAG)
        return ok
    
    def isReady(self, module=None):
        return self.checkStatus(module, MODULE_STATUS_READY)

    def dumpStatus(self):
        if (DEBUG): logD("dumpStatus", TAG)
        for key, value in self.module_status.items():
            if (DEBUG): logD("Module %s, status %d, msg %s"  % (key, value[0], value[2]))

    def reportIncident(self, severity=INCIDENT_SEVERITY_MIDDLE, reportFrom = None, msg = None):
        # Not show many log here, as it'll be written to incident report file
        logE("reportIncident, serverity %d" % severity, TAG)
        incident_msg = "%s,%d,%s,%s" % (common.current_time(common.TIME_FORMAT_TO_DISPLAY_SHORT),
                                            severity,
                                            str(reportFrom) if reportFrom is not None else "unknown",
                                            str(msg) if msg is not None else ""
                                            )
        try:
            __reportFild = None
            if not os.path.exists(INCIDENT_REPORT_FILE_PATH):
                incident_msg = "Time,Serverity,From,Message\n" + incident_msg
                __reportFild = open(INCIDENT_REPORT_FILE_PATH,"w")
            else:
                __reportFild = open(INCIDENT_REPORT_FILE_PATH,"a+")
            if __reportFild is not None:
                __reportFild.write("%s\n" % incident_msg)
                __reportFild.flush()
                __reportFild.close()
        except:
            traceback.print_exc()
            return False
        # TODO: Handle serverity, reboot, report, or anything else???
        return True

    def getIncidentReportFpath(self):
        if (DEBUG): logD("getIncidentReportFpath %s" % INCIDENT_REPORT_FILE_PATH, TAG)
        return INCIDENT_REPORT_FILE_PATH if os.path.exists(INCIDENT_REPORT_FILE_PATH) else None
    

g_systemreport = None

def sysReport():
    global g_systemreport
    if g_systemreport is None:
        g_systemreport = SystemReport()

    return g_systemreport


def init_system_report(app = None):
    log("init_system_report", toFile=True)

    # log("Init key dir %s", SYSTEM_REPORT_DIRECTORY, TAG)
    # if not os.path.exists(KEY_DIRECTORY):
    #     os.makedirs(KEY_DIRECTORY)
    
    log("Init system report dir %s", SYSTEM_REPORT_DIRECTORY, TAG)
    if not os.path.exists(SYSTEM_REPORT_DIRECTORY):
        os.makedirs(SYSTEM_REPORT_DIRECTORY)
    
    global g_systemreport
    g_systemreport = SystemReport()

    return common.ERR_NONE

def check_system(request):
    from server.app import get_resp
    if sysReport().isReady():
        return None
    else:
        if request.method == 'POST':
            return get_resp(
                error=-1, 
                message="SYSTEM NOT READY", 
                status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
        else:
            return redirect(url_for('setup'))