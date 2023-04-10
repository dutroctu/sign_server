#!/usr/bin/env python
#
#  Account info 
#

from server.app import app
import os
from server import common as common
import traceback
from .db_mgr import db

CONFIG_STATUS_NOT_READY = 0
CONFIG_STATUS_READY = 1
CONFIG_STATUS_DELETED = -1

class DbConfig(db.Document):
    metaData = db.StringField(required=True) # backup meta of db to db
    status = db.IntField(default=CONFIG_STATUS_NOT_READY)
    created_time = db.DateTimeField()
    last_update = db.DateTimeField()


