"""
Part of the SafeDroid v2.0 FrameWork.
Author : Arygriou Marios
Year : 2018
The framework is distributed under the GNU General Public License v3.0
"""

class Instance:
    def __init__(self):
        self.MD5 = ''
        self.name = 'none'
        self.api = []
        self.receiver = []
        self.permission = []
        self.isMalicious = 0
        self.appId = -1
        self.appToApiRelation = []
        self.appToPrmRelation = []

    def setMD5(self, md5):
        self.MD5 = md5

    def setName(self, name):
        self.name = name

    def setMalicious(self):
        self.isMalicious = 1

    def setappId(self, num):
        self.ApiId = num

    def addApi(self, a):
        self.api.append(a)

    def addPermission(self, p):
        self.permission.append(p)

    def addappToApiRelation(self, p):
        self.appToApiRelation.append(p)

    def addappToPrmRelation(self, p):
        self.appToPrmRelation.append(p)

    def getappToPrmRelation(self):
        return self.appToPrmRelation

    def getappToApiRelation(self):
        return self.appToApiRelation

    def getPermissions(self):
        return self.permission

    def getMalicious(self):
        return self.isMalicious

    def getappId(self):
        return self.ApiId

    def getMD5(self):
        return str(self.MD5)

    def getName(self):
        return self.name

    def getAPIlist(self):
        return self.api

    def printIns(self):
        if self.name:
            print 'Instance : ' + self.name + ' md5 checksum: ' + self.getMD5()
        else:
            print 'No name. md5 checksum: ' + self.getMD5()
        print 'API : '
        i = 0
        for a in self.api:
            print '\t' + str(i) + '.' + a
            i = i + 1
        print 'permissions : '
        for p in self.permission:
            print '\t' + p
        print 'receiver : '
        for r in self.receiver:
            print '\t' + r
        if self.isMalicious:
            print '\tMalicious application'
