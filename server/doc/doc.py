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

TAG = "help"
DOC_META_FNAME = "doclist"

def getHelpHtml(helpid):
    if (DEBUG): logD("getHelpHtml %s" % helpid, TAG)
    from server.app import getDocDir
    if helpid is not None and len(helpid) > 0:
        filemd = os.path.join(getDocDir(), "%s.md" % helpid)
        file = os.path.join(getDocDir(), helpid)
        html=None
        if (DEBUG): logD("file %s" % file, TAG)
        if (DEBUG): logD("filemd %s" % filemd, TAG)
        try:
            if (os.path.exists(filemd)):
                if (DEBUG): logD("read markdown", TAG)
                input_file = codecs.open(filemd, mode="r", encoding="utf-8")
                text = input_file.read()
                # extensions = ['extra', 'smarty', 'meta', 'sane_lists']
                # https://python-markdown.github.io/extensions/
                extensions = [
                    "markdown.extensions.abbr", 
                    "markdown.extensions.attr_list", 
                    "markdown.extensions.def_list", 
                    "markdown.extensions.md_in_html", 
                    "markdown.extensions.footnotes", 
                    "markdown.extensions.tables",
                    "markdown.extensions.sane_lists",
                    "markdown.extensions.wikilinks",
                    "markdown.extensions.toc",
                    "markdown.extensions.nl2br",
                    "markdown.extensions.fenced_code",
                ]
                html = markdown.markdown(text, extensions=extensions, output_format='html5')
            elif (os.path.exists(file)):
                if (DEBUG): logD("read raw file", TAG)
                html = common.read_string_from_file(file)
            else:
                html=None
        except:
            traceback.print_exc()
            logE("get help id %s failed" % helpid, TAG, True)
            html = None
        return html
    else:
        logE("Invalid input", TAG)
        return None

def readMdFile(filemd):
    if (DEBUG): logD("readMdFile %s" % filemd, TAG)
    from server.app import getDocDir
    html=None
    try:
        if (os.path.exists(filemd)):
            if (DEBUG): logD("read markdown", TAG)
            input_file = codecs.open(filemd, mode="r", encoding="utf-8")
            text = input_file.read()
            # extensions = ['extra', 'smarty', 'meta', 'sane_lists']
            # https://python-markdown.github.io/extensions/
            extensions = [
                "markdown.extensions.abbr", 
                "markdown.extensions.attr_list", 
                "markdown.extensions.def_list", 
                "markdown.extensions.md_in_html", 
                "markdown.extensions.footnotes", 
                "markdown.extensions.tables",
                "markdown.extensions.sane_lists",
                "markdown.extensions.wikilinks",
                "markdown.extensions.toc",
                "markdown.extensions.nl2br",
                "markdown.extensions.fenced_code",
            ]
            html = markdown.markdown(text, extensions=extensions, output_format='html5')
        else:
            html=None
    except:
        traceback.print_exc()
        logE("get help id %s failed" % filemd, TAG, True)
        html = None
    return html
    
def getDocList():
    if (DEBUG): logD("getDocList", TAG)
    from server.resource.res import getResList
    from server.app import getDocDir
    return getResList(getDocDir(), DOC_META_FNAME)

def convertToHtml(text):
    if (DEBUG): logD("convertToHtml %s" % text, TAG)
    if text is not None and len(text) > 0:
        try:
            # extensions = ['extra', 'smarty', 'meta', 'sane_lists']
            # https://python-markdown.github.io/extensions/
            extensions = [
                "markdown.extensions.abbr", 
                "markdown.extensions.attr_list", 
                "markdown.extensions.def_list", 
                "markdown.extensions.md_in_html", 
                "markdown.extensions.footnotes", 
                "markdown.extensions.tables",
                "markdown.extensions.sane_lists",
                "markdown.extensions.wikilinks",
                "markdown.extensions.toc",
                "markdown.extensions.nl2br",
                "markdown.extensions.fenced_code",
            ]
            html = markdown.markdown(text, extensions=extensions, output_format='html5')
        except:
            traceback.print_exc()
            logE("convert html %s failed" % text, TAG, True)
            html = None
        return html
    else:
        logE("Invalid input", TAG)
        return None