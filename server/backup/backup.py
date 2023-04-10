#!/usr/bin/env python
#

import os
from server import common as common

class IBackup(object):

    def doBackup(self, backupDir):
        return common.ERR_NOT_SUPPORT

    def doRestore(self, backupDir):
        return common.ERR_NOT_SUPPORT

    def getName(self):
        return None

