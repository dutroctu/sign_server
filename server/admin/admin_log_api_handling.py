#!/usr/bin/env python
#
#  KEY MANAGEMENT
#


from flask import send_file
from flask import render_template
from flask import request
from server.app import app
import os
from server.applog import log
from server.applog import logE
from server.applog import logD
from server.app import get_resp
from server import common as common
from server.login.login import is_login, current_username
from flask_login import login_required
from server import database as database
from server.app import DEBUG

TAG = "adminlog"


@app.route('/log', methods=['GET','POST'])
@login_required
def geloglist():
    log ("Received log request from '%s', method %s" % (request.remote_addr, request.method), TAG, toFile=True)
    login=is_login(request, database.account.ACCOUNT_TYPE_ADMIN)
    if login:
        from server.applog import getLogList
        loglist = getLogList()
        return render_template(
                "admin/log.html"
                , login=login
                , username=current_username()
                , account_type=database.account.ACCOUNT_TYPE_ID_CNAME
                , loglist=loglist
                )
    else:
        return get_resp(common.ERR_PROHIBIT, "Not login as admin yet", status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)

@app.route('/log/<logid>', methods=['GET','POST'])
@login_required
def gelog(logid):
    log ("Received log request from '%s', method %s" % (request.remote_addr, request.method), TAG, toFile=True)
    login=is_login(request, database.account.ACCOUNT_TYPE_ADMIN)
    if (DEBUG): logD("gelog %s" % logid, TAG)
    if login:
        from server.applog import getLogList
        loglist = getLogList()
        if logid is not None and len(logid) > 0:
            if logid in loglist:
                item = loglist[logid]
                if (DEBUG): logD("item %s" % item.toString(), TAG)
                resp = send_file(item.fpath, logid, as_attachment=True, attachment_filename=logid, cache_timeout=0) 
            else:
                resp = get_resp(400, "log %s not found" % logid)
            return resp
        else:
            return render_template(
                    "admin/log.html"
                    , login=login
                    , username=current_username()
                    , account_type=database.account.ACCOUNT_TYPE_ID_CNAME
                    , loglist=loglist
                    )
    else:
        return get_resp(common.ERR_PROHIBIT, "Not login as admin yet", status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)