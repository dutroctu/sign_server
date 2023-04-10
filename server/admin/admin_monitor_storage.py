#!/usr/bin/env python
#
#  MONITOR STORAGE API HANDLING
#


from flask import send_file
from flask import render_template
from flask import request
from server.app import app
import os
from server.applog import log
from server.applog import logE
from server.applog import logD
from server.applog import Log
from server.app import get_resp
from server import common as common
from server.login.login import is_login, current_username
from flask_login import login_required
from server import database as database
from server.app import DEBUG
from server.monitor.system_monitor import sysMon
from server.monitor.system_monitor import DUMP_QUEUE_LOG_FNAME
from server.monitor.system_monitor import DAYS_MIN,DAYS_MAX

TAG = "monitordisk"

log = Log(TAG)

# Main page of monitoring service
@app.route('/admin/monitorstorage', methods=['GET','POST'])
@login_required
def monitorStorage():
    log.i ("Received monitor disk request from '%s', method %s" % (request.remote_addr, request.method), toFile=True)
    login=is_login(request, database.account.ACCOUNT_TYPE_ADMIN) # require admin account
    if login:
                  
        from server.app import getRootDataDir
        from server.app import getRootTempDir
        from server.app import getRootInputDir
        from server.app import getRootOutputDir
        from server.app import getRootDownloadDir
        from server.app import getRootLogDir
        from server.app import getAutoDeleteTime
        import traceback
        if request.method == 'POST':
            req = request.args.get('req')
  
            # Scan/check size of storage
            if req is not None:
                if req == "checkstorage":
                    try:
                        # Query size of disk, size of critical folder
                        result = "\n\n********** Check Storage SIZE **********\n"
                        result += sysMon().checkStorage()
                        result += "\n\n********** Check Data Dir SIZE **********\n"
                        result += sysMon().checkDirSize(getRootDataDir())
                        result += "\n\n********** Check Tmp Dir SIZE **********\n"
                        result += sysMon().checkDirSize(getRootTempDir())
                        result += "\n\n********** Check Input Dir SIZE **********\n"
                        result += sysMon().checkDirSize(getRootInputDir())
                        result += "\n\n********** Check Output Dir SIZE **********\n"
                        result += sysMon().checkDirSize(getRootOutputDir())
                        result += "\n\n********** Check Download Dir SIZE **********\n"
                        result += sysMon().checkDirSize(getRootDownloadDir())
                        result += "\n\n********** Check Log Dir SIZE **********\n"
                        result += sysMon().checkDirSize(getRootLogDir())
                        return get_resp(
                                error=0, 
                                message=result,
                                status_code=common.ERR_HTTP_RESPONSE_OK)
                    except:
                        traceback.print_exc()
                        log.e("Check storage info failed")
                        return get_resp(
                            error=common.ERR_EXCEPTION, 
                            message="Check storage info failed, exception", 
                            status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
                
                # cleaup download folder
                elif req == "cleandownload":
                    # THIS IS CRITICAL ACTION, MAY CAUSE DELETE OTHER FOLDER IF SOMETHING WRONG OCCUR
                    daysparam = request.args.get('days')

                    # days: delete data older than "days" number
                    if (daysparam is not None and daysparam.isdigit()):
                        days = int(daysparam)
                        if days >= 0:
                            # let's cleanup
                            [ret, result] = sysMon().cleanupDownloadFolder(days)
                            if (ret == common.ERR_NONE):
                                return get_resp(
                                        error=common.ERR_NONE, 
                                        message=result, 
                                        status_code=common.ERR_HTTP_RESPONSE_OK)
                            else:
                                return get_resp(
                                    error=ret, 
                                    message=result, 
                                    status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
                        else:
                            log.e("days %d not support" % days)
                            return get_resp(
                                    error=common.ERR_INVALID_ARGS, 
                                    message="Date %d not support" % days, 
                                    status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
                    else:
                        log.e("Invalid days")
                        return get_resp(
                                error=common.ERR_INVALID_ARGS, 
                                message="invalid date", 
                                status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)

                elif req == "dumpreq": # Dump req queue in monitor service
                    try:
                        # Fix url path to log, FIXME please, make it dynamically
                        sysMon().addDumpReq2Queue()
                        return get_resp(
                                error=0, 
                                message="Please check Dump log '%s' in <a href='/log'>Log</a>, may need to wait"  % DUMP_QUEUE_LOG_FNAME,
                                status_code=common.ERR_HTTP_RESPONSE_OK)
                    except:
                        traceback.print_exc()
                        log.e("Dump req queue failed")
                        return get_resp(
                            error=common.ERR_EXCEPTION, 
                            message="Dump req queue failed, exception", 
                            status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
                
                else:
                    log.e("Invalid Request")
                    return get_resp(
                            error=common.ERR_INVALID_ARGS, 
                            message="invalid request", 
                            status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
            else:
                log.e("No Request")
                return get_resp(
                        error=common.ERR_INVALID_ARGS, 
                        message="No request", 
                        status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
        else:
            #it's GET so return render html to show on browser
            return render_template(
                    "admin/monitor_storage.html"
                    , login=login
                    , username=current_username()
                    , account_type=database.account.ACCOUNT_TYPE_ID_CNAME
                    , datadir=getRootDataDir()
                    , tmpdir=getRootTempDir()
                    , inputdir=getRootInputDir()
                    , outputdir=getRootOutputDir()
                    , downloaddir=getRootDownloadDir()
                    , logdir=getRootLogDir()
                    , min_day=DAYS_MIN
                    , max_days=DAYS_MAX
                    , auto_delete_time=getAutoDeleteTime()
                    )
    else:
        return get_resp(common.ERR_PROHIBIT, "Not login as admin yet", status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
