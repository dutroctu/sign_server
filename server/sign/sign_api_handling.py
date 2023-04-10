#!/usr/bin/env python
#
#  COMMON CLASS FOR SIGNING
#


from flask import Flask
from flask_restful import Api, Resource, reqparse
from flask import send_file
from flask import render_template
from flask import request, abort, jsonify, send_from_directory
from server.app import app
from server.app import main
from server.app import KEEP_OUTPUT_FILE
import os
from server.applog import log
from server.applog import logE
from server.applog import logD
from server.applog import Log
from server.sign.signreq import SignRequest
from server.sign.signfactory import SignFactory
from server.app import get_resp
import shutil
from server.login.login import is_login, current_username
from server.sign.signresp import SignResp
from server.fota.fotagenresp import FotaGenResp
from flask_login import login_required, current_user
from flask import  Blueprint

from server import common
from server.app import DEBUG
TAG="sign"

logit = Log(TAG)

# Access to /sign, show all modules which support signing for user select
@app.route('/sign', methods=['GET'])
@login_required
def sign():
    log ("Received sign from '%s'" % (request.remote_addr), toFile=True)
    return render_template('sign/sign.html', modules = SignFactory.get_sign_tool_list(), login=is_login(request), username=current_username())

#download page
@app.route("/download/<sessionid>")
@login_required
def get_download_file(sessionid):
    """Download file."""
    session = SignFactory.getSession(sessionid)
    SignFactory.dumpSession(sessionid)
    logit.i ("Received Download request for'%s' from '%s'" % (sessionid, request.remote_addr), True)
    if (session is not None):
        if (session.data is None):
            resp = get_resp(400, "no data")
        signResp = session.data
        if isinstance(signResp, SignResp) or isinstance(signResp, FotaGenResp):
            fname = request.args.get('fname') # get download file
            if (fname is not None) and len(fname) > 0:
                if (DEBUG): logD("get path for %s" %(fname))
                if fname in signResp.download_file_list: # check to get real path
                    if os.path.exists(signResp.download_file_list[fname]):
                        # send file to caller
                        if (DEBUG): logD("send file %s path %s" %(fname, signResp.download_file_list[fname]))
                        resp = send_file(signResp.download_file_list[fname], fname, as_attachment=True)
                    else:
                        resp = get_resp(400, "file not found")
                else:
                    resp = get_resp(400, "file name not found")
            else:
                resp = get_resp(400, "file name invalid")
        else:
            resp = get_resp(400, "session not found")
    else:
        resp = get_resp(400, "invalid session")
    
    if (DEBUG): logD(resp)
    return resp

# Access to specific sign module
# GET: access from browser, POST: send sign request
@app.route('/sign/<name>', methods=['GET','POST'])
@login_required
def sign_module(name):
    error=""

    logit.i ("Received signing request for'%s' from '%s'" % (name, request.remote_addr), toFile=True)

    # get sign tool basing on module name
    __sign_tool = SignFactory.get_sign_tool_by_name(name)

    # if any action is set for this signing tool? i.e. download, get help
    action = request.args.get('action', default = None)

    # not found sign tool
    if __sign_tool is None:
        return get_resp(400, "Not FOUND module")
    
    if action is None: # no action, let handle as default one
        # POST request, mean signing request from client
        if request.method == 'POST':   
            # log ("request %s" % request.form)

            # parse sign requests
            __req = __sign_tool.parse_request(request)

            if __req is None:
                logE("Parse request failed")
                return get_resp(400, "Parse request failed")
        
            #do sign
            signResp = __sign_tool.sign(__req)

            if (signResp is not None and signResp.resp_code == 0): #OK send file to client
                logit.i ("Signing request for'%s' from '%s' Done" % (name, request.remote_addr), True)
                if (__req.zip_output): # zip the output file
                    if (signResp.zip_file is not None): # send zip file to caller
                        log("OK, send file to client %s" % signResp.zip_file, TAG, True)
                        resp = send_file(signResp.zip_file,as_attachment=True)
                    else:
                        resp = get_resp(400, "zip file not found")
                elif (__req.output_resp):
                    if (DEBUG): logD("Output in response: %s" % signResp.resp_msg)
                    import json
                    resp = get_resp(common.ERR_HTTP_RESPONSE_OK, json.loads(signResp.resp_msg))
                else: # re-direct to download page
                    if (DEBUG): logD("render download page for session %s" % signResp.sign_req.session.uuid)
                    resp = render_template('download.html', download_id = signResp.sign_req.session.uuid, 
                                files = signResp.download_file_list, login=is_login(request), username=current_username())
                
            else:
                logit.i ("Signing request for'%s' from '%s' Failed" % (name, request.remote_addr), True)
                if (signResp is not None) and not KEEP_OUTPUT_FILE: # clean up response
                    signResp.clean()
                resp = get_resp(400, signResp.resp_msg)

            if not KEEP_OUTPUT_FILE:
                if (DEBUG): logD("Check to remove temp file")
                # clean up request data
                if (__req is not None):
                    __req.clean()

                SignFactory.clearSession() # check to clear session
            else:
                if (DEBUG): logD("Not remove temp file")
            
            # logD("resp %s" % resp)
            return resp

        #it's GET so return render html to show on browser
        return __sign_tool.get_html_render_for_manual_sign(request)
    else: # action is specified, let do action instead
        log("Sign Action %s" % action, TAG)
        if action == common.ACTION_HELP: # help action
            if (DEBUG): logD("Call help" , TAG)

            # TODO: handle GET/POST method
            html = __sign_tool.get_help(request)
            if html is not None:
                if (DEBUG): logD("help %s" % html , TAG)
                if request.method == 'POST':
                    return get_resp(0, html, status_code=common.ERR_HTTP_RESPONSE_OK)
                else:
                    from flask import render_template_string
                    return render_template_string(html)
            else:
                logE("Invalid help info", TAG)
                return get_resp(
                    error=common.ERR_INVALID_ARG, 
                    message="No help info", 
                    status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)
        
        elif action == common.ACTION_DOWNLOAD: # download action
            if (DEBUG): logD("Call download" , TAG)
            path = __sign_tool.get_download_file(request)

            if (DEBUG): logD("path %s" % path , TAG)

            if common.isValidString(path) is not None and os.path.exists(path):
                log("Send file to client", TAG)
                fname = os.path.basename(path)
                return send_file(path, fname, as_attachment=True)
            else:
                logE("No download info", TAG)
                return get_resp(
                    error=common.ERR_FAILED, 
                    message="No download info", 
                    status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)

        else: # unknow action
            logE("unknown action %s" % action, TAG)
            return get_resp(
                error=common.ERR_FAILED, 
                message="unknown action %s" % action, 
                status_code=common.ERR_HTTP_RESPONSE_BAD_REQ)

@app.route('/renesas_ic_param', methods=['GET','POST'])
@login_required
def renesas_ic_param_list():
    logit.i ("Received renesas_ic_param_list request from '%s', method %s" % (request.remote_addr, request.method), True)
    from server.sign.renesas_ic_param import getListParam
    from server.sign.signrenesas_ic import RENESAS_IC_TOOL_NAME
    param_list = getListParam()
    # POST request, mean signing request from client
    if request.method == 'POST':   

        # FIXME
        resp = get_resp(200, "OK", {"param_list": param_list})
        return resp

    #it's GET so return render html to show on browser
    return render_template(
            "sign/list_ic_param.html"
            , login=is_login(request)
            , username=current_username()
            , toolname=RENESAS_IC_TOOL_NAME
            , param_list=param_list
            )

@app.route('/cep_key_param', methods=['POST'])
@login_required
def cep_key_param():
  __sign_tool = SignFactory.get_sign_tool_by_name("cep")
  __req = __sign_tool.parse_request(request)
  return jsonify(__sign_tool.getPublicKey(__req))

# Access to specific sign module
# GET: access from browser, POST: send sign request
@app.route('/sign/tbox_cep', methods=['POST'])
@login_required
def sign_tbox_cep():
    logit.i ("Received signing request for'%s' from '%s'" % ("tbox_cep", request.remote_addr), toFile=True)

    # get sign tool basing on module name
    __sign_tool = SignFactory.get_sign_tool_by_name("cep")

    # if any action is set for this signing tool? i.e. download, get help
    action = request.args.get('action', default = None)

    # not found sign tool
    if __sign_tool is None:
        return get_resp(400, "Not FOUND module")
    resp = None
    if action is None: # no action, let handle as default one
        # POST request, mean signing request from client
        if request.method == 'POST':   
            # parse sign requests
            __req = __sign_tool.parse_request(request)

            if __req is None:
                logE("Parse request failed")
                return get_resp(400, "Parse request failed")
        
            #do sign
            signResp = __sign_tool.sign(__req)

            if (signResp is not None and signResp.resp_code == 0): #OK send file to client
                logit.i ("Signing request for'%s' from '%s' Done" % ("cep", request.remote_addr), True)
                # signResp.sign_req.session.uuid
                print(signResp.download_file_list)
                print(__req.outfile)
                return send_file(signResp.download_file_list[__req.outfile], __req.outfile, as_attachment=True)
                # return get_resp(200, "ok")
                
            else:
                logit.i ("Signing request for'%s' from '%s' Failed" % ("cep", request.remote_addr), True)
                if (signResp is not None) and not KEEP_OUTPUT_FILE: # clean up response
                    signResp.clean()
                resp = get_resp(400, signResp.resp_msg)

            if not KEEP_OUTPUT_FILE:
                if (DEBUG): logD("Check to remove temp file")
                # clean up request data
                if (__req is not None):
                    __req.clean()

                SignFactory.clearSession() # check to clear session
            else:
                if (DEBUG): logD("Not remove temp file")
        else:
            resp = get_resp(400, "invalid method")
    else:
        # logD("resp %s" % resp)
        resp = get_resp(400, "invalid action")
    return resp