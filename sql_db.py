"""
Part of the SafeDroid v2.0 FrameWork.
Author : Arygriou Marios
Year : 2017
The framework is distributed under the GNU General Public License v3.0
"""
import MySQLdb
from _mysql_exceptions import OperationalError, ProgrammingError
import logging


class Config:
    def __init__(self, cname):
        self.c = {}
        with open(cname, 'r') as f:
            for line in f:
                ff = line.split(':')
                self.c[''.join(ff[0].split())] = ''.join(ff[1].split())

    def schema(self):
        return self.c['schema']

    def host(self):
        return self.c['host']

    def password(self):
        return self.c['password']

    def username(self):
        return self.c['username']


class SafeDroidDB:
    def __init__(self, create):
        self.log = logging.getLogger('SafeDroid.SQLDatabase')
        self.config = Config('database.conf')
        self.initConnection()
        self.cursor = self.db.cursor()
        if create == True:
            self.createTables()

    def initConnection(self):
        try:
            self.db = MySQLdb.connect(self.config.host(), self.config.username(
            ), self.config.password(), self.config.schema())
        except OperationalError:
            self.buildDB()
            self.db = MySQLdb.connect(self.config.host(), self.config.username(
            ), self.config.password(), self.config.schema())
            self.log.info('Create schema %s @ %s') % (
                self.config.schema(), self.config.host())
        return

    def buildDB(self):
        db = MySQLdb.connect(self.config.host(),
                             self.config.username(), self.config.password())
        cursor = db.cursor()
        q = " CREATE DATABASE `%s`; " % self.config.schema()
        try:
            cursor.execute(q)
        except:
            self.log.critical('Failed to create %s schema' %
                              self.config.schema())
            pass
        self.log.info('Creating schema %s..Success' % self.config.schema())
        cursor.close()

    def resetCursor(self):
        try:
            self.cursor.close()
        except Exception, err:
            self.log.info('Cursor closed. Re-setting cursor..Success')
        self.cursor = self.db.cursor()
        return

    def dropTable(self, name):
        d = MySQLdb.connect(self.config.host(), self.config.username(
        ), self.config.password(), self.config.schema())
        c = d.cursor()
        q = "DROP TABLE " + name
        try:
            c.execute(q)
            self.log.info('Delete table:`%s`..Success' % name)
        except:
            pass
        c.close()

    def createTables(self):
        # APPLICATIONS TABLE
        tab_appl = """CREATE TABLE `%s`.`APPLICATIONS` 
                    ( `AppId` INT UNSIGNED NOT NULL AUTO_INCREMENT ,
                    `Name` VARCHAR(100) NOT NULL DEFAULT 'nameless' ,
                    `Md5` VARCHAR(32) NOT NULL ,
                    `IsMalicious` TINYINT NOT NULL DEFAULT '0',
                    PRIMARY KEY (`AppId`),
                    UNIQUE `AppId` (`AppId`))
                    ENGINE = InnoDB;""" % self.config.schema()

        self.executeQuery(tab_appl, False)

        # API TABLE
        tab_api = """CREATE TABLE `%s`.`API` 
                    ( `ApiId` INT UNSIGNED NOT NULL AUTO_INCREMENT ,
                    `Name` VARCHAR(100) NOT NULL DEFAULT 'none' ,
                    `MalOcc` INT NOT NULL DEFAULT '0' , 
                    `BenOcc` INT NOT NULL DEFAULT '0' ,
                    `Ratio`  FLOAT NOT NULL DEFAULT '0.0',
                    PRIMARY KEY (`ApiId`))
                    ENGINE = InnoDB;""" % self.config.schema()

        self.executeQuery(tab_api, False)

        # PERMISSION TABLE
        tab_prm = """CREATE TABLE `%s`.`PERMISSION` 
                    ( `PrmId` INT UNSIGNED NOT NULL AUTO_INCREMENT ,
                    `Name` VARCHAR(100) NOT NULL DEFAULT 'none' ,
                    `MalOcc` INT NOT NULL DEFAULT '0' , 
                    `BenOcc` INT NOT NULL DEFAULT '0' ,
                    `Ratio`  FLOAT NOT NULL DEFAULT '0.0',
                    PRIMARY KEY (`PrmId`))
                    ENGINE = InnoDB;""" % self.config.schema()

        self.executeQuery(tab_prm, False)

        # APPtoPRM
        tab_a2p = """CREATE TABLE `%s`.`APPtoPRM`
                    (`AppId` INT UNSIGNED NOT NULL,
                    `PrmId` INT UNSIGNED NOT NULL,
                    PRIMARY KEY pk_APPtoPRM (`AppId`,`PrmId`))
                    ENGINE = InnoDB;
                    """ % self.config.schema()

        self.executeQuery(tab_a2p, False)

        # APPtoAPI
        tab_a2a = """CREATE TABLE `%s`.`APPtoAPI`
                    (`AppId` INT UNSIGNED NOT NULL,
                    `ApiId` INT UNSIGNED NOT NULL,
                    PRIMARY KEY pk_APPtoAPI (`AppId`,`ApiId`))
                    ENGINE = InnoDB; 
                    """ % self.config.schema()

        self.executeQuery(tab_a2a, False)

    def insertToTable(self, tname, md5, name, isMalicious):
        ''' @arg : table name , md5 , name (app or api) , isMalicious {0,1}
            @ret : the id of the last inserted entry
        '''
        if 'APPLICATIONS' in tname:
            ins = """ INSERT INTO `APPLICATIONS` (`Name`, `Md5`, `IsMalicious`)
                        VALUES ('%s' , '%s' , %d); """ % (name, md5, isMalicious)
            # return AppId
            ret = """SELECT `AppId` FROM `APPLICATIONS` WHERE `Md5` = '%s' """ % md5

        if 'API' in tname:
            if isMalicious == 1:
                ins = """ INSERT INTO `API` (`Name`, `MalOcc`)
                        VALUES ('%s' , 1); """ % name
            else:
                ins = """ INSERT INTO `API` (`Name`, `BenOcc`)
                        VALUES ('%s' , 1); """ % name
            # return ApiId
            ret = """SELECT `ApiId` FROM `API` WHERE `Name` = '%s' """ % name

        if 'PERMISSION' in tname:
            if isMalicious == 1:
                ins = """INSERT INTO `PERMISSION` (`Name`, `MalOcc`)
                        VALUES ('%s', 1); """ % name
            else:
                ins = """INSERT INTO `PERMISSION` (`Name`, `MalOcc`)
                        VALUES ('%s', 1); """ % name
            # return PrmId
            ret = """SELECT `PrmId` FROM `PERMISSION` WHERE `Name` = '%s' """ % name

        self.executeQuery(ins, False)
        return self.executeQuery(ret, True)[0]

    def duplicateApi(self, tname, name, isMalicious):
        ''' 
        @ret : [-1] upon abscence , id and (mal_cnt or ben_cnt) otherwise
        '''
        exs = "SELECT * FROM `API` WHERE `Name` = '%s' " % name

        row = self.executeQuery(exs, True)

        if row is None:
            return [-1]

        if isMalicious:  # ret id , mal_cnt
            return [row[0], row[2]]
        else:  # ret id, ben_cnt
            return [row[0], row[3]]

    # 0: id , 1: name , 2:MalOcc, 3:BenOcc
    # return None or 'exists' if entry exists, id and (mal_cnt or ben_cnt) otherwise

    def duplicatePermission(self, name, isMalicious):
        ''' @arg :
            @ret : [-1] upon abscence , id and (mal_cnt or ben_cnt) otherwise
        '''
        exs = "SELECT * FROM `PERMISSION` WHERE `Name` = '%s' " % name

        row = self.executeQuery(exs, True)

        if row is None:
            return [-1]

        if isMalicious:  # ret id , mal_cnt
            return [row[0], row[2]]
        else:  # ret id, ben_cnt
            return [row[0], row[3]]

    def updateToTable(self, tname, id=None, md5=None, mal_cnt=None, ben_cnt=None, isMalicious=None, ratio=None):
        table_list = set(('APPLICATIONS', 'API', 'PERMISSION'))
        if ('API' in tname in table_list):
            if mal_cnt != None:
                upd = """ UPDATE `%s` SET `MalOcc`= %d WHERE `ApiId` = '%d' """ % (
                    tname, mal_cnt, id)
                self.executeQuery(upd, False)

            if ben_cnt != None:
                upd = """ UPDATE `%s` SET `BenOcc`= %d WHERE `ApiId` = '%d' """ % (
                    tname, ben_cnt, id)
                self.executeQuery(upd, False)

            if ratio != None:
                upd = """ UPDATE `%s` SET `Ratio`= %f WHERE `ApiId` = '%d' """ % (
                    tname, ratio, id)
                self.executeQuery(upd, False)

            if isMalicious != None:
                upd = """ UPDATE `%s` SET `IsMalicious`= %d WHERE `AppId` = '%d' """ % (
                    tname, isMalicious, id)
                self.executeQuery(upd, False)

        elif ('PERMISSION' in tname in table_list):
            if mal_cnt != None:
                upd = """ UPDATE `%s` SET `MalOcc`= %d WHERE `PrmId` = '%d' """ % (
                    tname, mal_cnt, id)
                self.executeQuery(upd, False)

            if ben_cnt != None:
                upd = """ UPDATE `%s` SET `BenOcc`= %d WHERE `PrmId` = '%d' """ % (
                    tname, ben_cnt, id)
                self.executeQuery(upd, False)
            if ratio != None:
                upd = """ UPDATE `%s` SET `Ratio`= %f WHERE `PrmId` = '%d' """ % (
                    tname, ratio, id)
                self.executeQuery(upd, False)
            if isMalicious != None:
                upd = """ UPDATE `%s` SET `IsMalicious`= %d WHERE `PrmId` = '%d' """ % (
                    tname, isMalicious, id)
                self.executeQuery(upd, False)

    def insertRelation(self, AppId, ApiIdList):
        ''' @arg :
            @ret :
        '''
        if len(ApiIdList) == 0:
            return
        join = """ INSERT INTO `APPtoAPI` (`AppId`, `ApiId`)
                        VALUES """
        l = ''

        for api in ApiIdList:
            l += '(%d,%d),' % (AppId, api)
        rel = l[:-1]+';'
        join += rel

        self.executeQuery(join, False)

    def insertAppToPrmRelation(self, AppId, PrmIdList):
        ''' @arg :
            @ret :
        '''
        if len(PrmIdList) == 0:
            return
        join = """INSERT INTO `APPtoPRM` (`AppId` , `PrmId`)
                    VALUES """
        l = ''
        for perm in PrmIdList:
            l += '(%d,%d),' % (AppId, perm)
        rel = l[:-1]+';'
        join += rel

        self.executeQuery(join, False)

    def setRatio(self, tname):
        q = """SELECT COUNT(1) FROM `%s` """ % tname
        numberofrows = self.executeQuery(q, True)[0]

        if 'API' in tname:
            idname = 'ApiId'
        elif 'PERMISSION' in tname:
            idname = 'PrmId'
        for row in range(1, numberofrows):
            r = """SELECT `MalOcc`,`BenOcc` FROM `%s` WHERE `%s` = '%d' """ % (
                tname, idname, row)
            result = self.executeQuery(r, True)
            ratio = result[0] / float(result[0] + result[1])
            self.updateToTable(tname, row, ratio=ratio)
        return

    def executeQuery(self, query, retvalue):
        try:
            self.cursor.execute(query)
            self.db.commit()
            self.log.debug(query)
        except Exception, err:
            self.db.rollback()
            self.resetCursor()
            self.log.error('%s\n%s' % (query, err))
            return None
        if retvalue:
            result = self.cursor.fetchone()
            self.resetCursor()
            return result
        self.resetCursor()
        return None

    def exists(self, tname, md5, name):
        '''@arg : table name , md5 , name (app or api) , isMalicious {0,1}
           @ret : True , False
        '''
        if 'APPLICATIONS' in tname:
            q = """SELECT * FROM `APPLICATIONS` WHERE `Md5` = '%s' AND `Name`='%s'; """ % (
                md5, name)

        ans = self.executeQuery(q, True)
        if ans is None:
            return False

        qq = """ SELECT * FROM `APPtoAPI` WHERE `AppId` = %d""" % ans[0]
        return True if self.executeQuery(qq, True) is not None else False
