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

from server.app import KEEP_OUTPUT_FILE
import os
from server.applog import log
from server.applog import logE
from server.applog import logD
from server.app import get_resp
import shutil
from flask_login import login_required
from server.login.login import is_login, current_username
from server.fota.fotagentool import FotaTool
from server.app import DEBUG
TAG = "fota"
# Key to be used
KEY_TYPE_LIST = [
    "test",
    # "release" # TODO: suport release key or integrate with key management
    ]
    
# List of Module handled by FOTA
MODULE_LIST = [
    "tbox",
    "xgw",
    "mhu",
    ]

TAG = "fota"


fota_tool = FotaTool()

# GET: access from browser, POST: send fota request
@app.route('/fota', methods=['GET','POST'])
@login_required
def get_fota():
    error=""

    log ("Received fota request for from '%s'" % ( request.remote_addr), TAG, True)

    # POST request, mean fota request data from client
    if request.method == 'POST':   

        # parse fota requests
        __req = fota_tool.parse_request(request)

        # parsed failed, return
        if __req is None:
            logE("Parse request failed")
            return get_resp(400, "Parse request failed")
    
        #do fota
        fotaResp = fota_tool.gen_fota(__req)

        if (fotaResp is not None and fotaResp.resp_code == 0): #OK send file to client
            if (__req.zip_output): # zip the output file, should be used in API call
                if (fotaResp.zip_file is not None): # send zip file to caller
                    log("OK, send file to client %s" % fotaResp.zip_file, TAG, True)
                    resp = send_file(fotaResp.zip_file,as_attachment=True)
                else:
                    resp = get_resp(400, "zip file not found")
            else: # re-direct to download page
                if (DEBUG): logD("render download page for session %s" % fotaResp.fota_req.session.uuid)
                resp = render_template('download.html', download_id = fotaResp.fota_req.session.uuid, 
                            files = fotaResp.download_file_list, login=is_login(request), username=current_username())
            # TODO: support to send json which contains download link
        else:
            if (fotaResp is not None) and not KEEP_OUTPUT_FILE: # clean up response
                fotaResp.clean()
            resp = get_resp(400, fotaResp.resp_msg)


        if not KEEP_OUTPUT_FILE: # check if we should keep output file for debug
            if (DEBUG): logD("Check to remove temp file")
            # clean up request data
            if (__req is not None):
                __req.clean()
            
            #re-use session mangament of Sign modules
            from server.sign import signfactory
            signfactory.SignFactory.clearSession() # check to clear session
        else:
            if (DEBUG): logD("Not remove temp file")
        
        if (DEBUG): logD("resp %s" % resp)
        return resp

    #it's GET so return render html to show on browser
    return fota_tool.get_html_render_for_manual_sign(request)