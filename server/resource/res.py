#!/usr/bin/env python
#
#  HELP
#


from flask import Flask
from flask_restful import Api, Resource, reqparse
from flask import send_file
from flask import render_template
from flask import request, abort, jsonify, send_from_directory
from server.app import app
from server.app import getModelList
from server.app import getProjectList
from server.app import KEEP_OUTPUT_FILE
from server.app import DEBUG
from server.app import is_debug_db
from server.app import ROOT_DIR
import os
from server.applog import log
from server.applog import logE
from server.applog import logD
from server.app import get_resp
from server import common as common
import traceback
import shutil
import codecs
import markdown
from server.app import DEBUG
TAG = "resource"
RES_META_FNAME = "reslist"

def getResPath(resid, res_dir=None, metafname=None):
    if (DEBUG): logD("getResPath %s" % resid, TAG)
    from server.app import getResDir
    res_dir = getResDir() if res_dir is None else res_dir
    metafname = RES_META_FNAME if metafname is None else metafname
    path = None
    for filename in os.listdir(res_dir):
        if (DEBUG): logD("Found %s" % filename)
        if filename != RES_META_FNAME:
            tmp = os.path.splitext(filename)
            if tmp is not None and len(tmp) > 0:
                id = tmp[0].strip()
                if len(id) > 0 and resid == id:
                    path = os.path.join(res_dir, filename)
                    break
    return path

def getResList(res_dir=None, metafname=None, ignorefname=None):
    if (DEBUG): logD("getResList", TAG)
    from server.app import getResDir
    res_dir = getResDir() if res_dir is None else res_dir
    metafname = RES_META_FNAME if metafname is None else metafname
    metafile = os.path.join(res_dir, metafname)
    ignoreFile = None
    if common.isValidString(ignorefname) is not None:
        ignoreFile = os.path.join(res_dir, ignoreFile)
        if not os.path.exists(ignoreFile):
            ignoreFile = None
    

    
    if (DEBUG): logD("res_dir %s" % res_dir, TAG)
    if (DEBUG): logD("metafile %s" % metafile, TAG)
    ignoreList=[]
    if ignoreFile is not None:
        if (DEBUG): logD("ignoreFile %s" % ignoreFile, TAG)
        try:
            with open(ignoreFile) as f:
                content = f.readlines()
            
            for x in content:
                val = common.isValidString(x)
                if val is not None and (not val.startswith("#")):
                    ignoreList.append(x)
                if (DEBUG): logD("ignoreList %s" % str(ignoreList))
        except:
            traceback.print_exc()
            logE("parse ignore list failed", TAG)


    res_list = {}
    # parse meta file.
    # each resource is in each line
    # <resource id>,<title>
    if os.path.exists(metafile):
        if (DEBUG): logD("Found meta, try to parse")
        with open(metafile) as f:
            content = f.readlines()
        
        for x in content:
            if (x is not None) and (not x.startswith("#")):
                splits = x.strip().split(",", 1)
                if splits is not None and len(splits) > 0:
                    id = splits[0].strip() if splits[0] is not None else ""
                    name = splits[1].strip() if len(splits) > 1 else ""
                    if len(id) > 0:
                        res_list[id] = name if len(name) > 0 else id
        if (DEBUG): logD("res_list %s" % str(res_list))
    else:
        if (DEBUG): logD("not found meta file")
    
    # check list of file if match with res_dir
    file_list = []
    if (DEBUG): logD("Search file in %s" % res_dir)
    for filename in os.listdir(res_dir):
        if (DEBUG): logD("Found %s" % filename)
        if filename != metafname:
            tmp = os.path.splitext(filename)
            if tmp is not None and len(tmp) > 0:
                id = tmp[0].strip()
                if len(id) > 0:
                    file_list.append(id)
                    if id not in res_list:
                        res_list[id] = filename
    
    if (DEBUG): logD("file_list %s" % str(file_list))

    if len(res_list) > 0:
        for id in list(res_list.keys()):
            if id not in file_list or id in ignoreList:
                del res_list[id]
    
    if (DEBUG): logD("res_dir %s" % str(res_list))
    return res_list

