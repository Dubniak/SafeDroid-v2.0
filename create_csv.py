"""
Part of the SafeDroid v2.0 FrameWork.
Author : Arygriou Marios
Year : 2017
The framework is distributed under the GNU General Public License v3.0
"""
import MySQLdb 
import csv
import os
from sql_db import Config

def createFile(tname):
	config = Config('database.conf')
	db = MySQLdb.connect(config.host(), config.username(), config.password(), config.schema())
	cursor = db.cursor()
	fname = tname.lower() + '.csv'
	q = "SELECT * FROM `%s`" %tname
	cursor.execute(q)
	result = cursor.fetchall()
	fp = open(os.path.join('data_pool',fname),'w')
	myFile = csv.writer(fp)
	myFile.writerows(result)
	fp.close()
    

def createDir():
	if not os.path.exists('data_pool'):
		os.mkdir('data_pool')
        
