"""
Part of the SafeDroid v2.0 FrameWork.
Author : Arygriou Marios
Year : 2018
The framework is distributed under the GNU General Public License v3.0
"""

from preparation import Preparation
from servant import Servant
from sql_db import SafeDroidDB
from instance import Instance
from androwarn_reverse import getAPIfromPkg

import os
import multiprocessing
from functools import partial		#for passing multiple arguments to a parallel execution function
from contextlib import contextmanager



#need to handle two objects, prepared and servant
#use multiprocessing outside of class



@contextmanager
def poolcontext(*args, **kwargs):
	pool = multiprocessing.Pool(*args, **kwargs)
	yield pool
	pool.terminate()	

'''
	@arg	: Mode of execution as selected by the user
	@arg	: Preparation object
	@ret	: Appropriateexecution method
	@use	: Dispatcher of execution mode
'''	
def execution_dispatch(mode, prepared):
	dispatcher = {'FOLDERS':execute_directory, 'SINGLE':execute_single}
	servant = Servant()
	return dispatcher[mode](prepared, servant)
	

'''
	@arg	: Preparation object
	@arg	: Servant object
	@ret	: n/a
	@use	: Execution routine for FOLDER mode
'''	
def execute_directory(prepared, servant):
	#self.prepared.inform('folders executing..')
	prepared.set_size(servant.get_directory_size_bytes(prepared.get_malicous_directory(), prepared) + servant.get_directory_size_bytes(prepared.get_benign_directory(), prepared))
	print 'Size is %s' %prepared.get_size()
	size_mal = 0
	size_ben = 0
	perv = 0
	number_of_files = 0
	fl = File_List(len(prepared.get_file_list()), multiprocessing.cpu_count(), prepared.get_file_list(), 0)
	sub = fl.getSublists()
	with poolcontext(processes=multiprocessing.cpu_count()) as pool:
		pool.map(partial(_reverse_Analysis, malicious_directory = prepared.get_malicous_directory()), sub)
	
	print 'Ending'
	


'''
	@arg	: List(s) containing the absolute path to apks
	@arg	: String to absolute path to malicious directory 
	@ret	: Info event entry for log
	@use	: Reverse analysis of apk by employing AndroWarm functionality. Insertion of analysis results to database.
'''
def _reverse_Analysis(sources, malicious_directory):
	db = SafeDroidDB(False)
	event_log = {}
	for f in sources:
		mal = 0
		event_log['info'] = 'Application examined: %s' % f
		if (malicious_directory in f):
			mal = 1
		try:
			data = getAPIfromPkg(f)
			entry, event_log['info'] = _parse_data(data, mal)
			if db.exists('APPLICATIONS', entry.getMD5(), entry.getName()):
				continue
			insertToDB(entry, db)
			db.insertRelation(entry.getappId(), uniquate_list(entry.getappToApiRelation()))
			db.insertAppToPrmRelation(entry.getappId(), uniquate_list(entry.getappToPrmRelation()))
		except Exception, err:
			event_log['critical'] = '%s failed. %s' % (f,err)
			pass
	return event_log



'''
	@arg	: Parsed data relevant to apk
	@arg	: Nature of apk
	@ret	: Instance containing relevant data for the analyzed apk
	@ret	: Info event entry for log
'''
def _parse_data(data, isMalicious):
    i = 0  # multipurpose counter
    inst = Instance()
    flag = False
    if data:
        for item in data:

            for category, element_tuple in item.iteritems():
                for name, content in element_tuple:
                    if content and isinstance(name, str):
                        for element in content:
                            if (name is 'activities' and not flag):
                                inst.setName(
                                    '.'.join(element.split('.')[:-1])[:100])
                                flag = True
                            if (name is 'fingerprint' and 'MD5' in element):  # MD5
                                inst.setMD5(element[5:])
                            if (name is 'permissions'):  # permissions
                                inst.addPermission(element)
                                i += 1
                            if (name is 'classes_list' or name is 'internal_classes_list' or name is 'external_classes_list' or name is 'internal_packages_list' or name is 'external_packages_list'):  # API
                                inst.addApi(element[:100])

    #log.info("%s has %d API and %d permissions" % (str(inst.getMD5()),
    #                                              len(inst.getAPIlist()), len(inst.getPermissions())))
    if isMalicious:
        inst.setMalicious()
    return inst, '%s has %d API and %d permissions' % (str(inst.getMD5()),
                                                   len(inst.getAPIlist()), len(inst.getPermissions()))


''' 
	@arg	: Instance containing relevant data for the analyzed apk
	@arg	: databese connector to sql locahost
    @ret	: n/a
'''
def insertToDB(entry, db):

    mal = entry.getMalicious()

    # set entry's api id alongside insertion
    entry.setappId(db.insertToTable(
        'APPLICATIONS', entry.getMD5(), entry.getName(), mal))

    apis = entry.getAPIlist()
    i = 0

    # insert API
    dist_api = uniquate_list(entry.getAPIlist())

    for api in dist_api:

        a = db.duplicateApi('API', api, mal)

        if (a[0] == -1):  # new API
            entry.addappToApiRelation(db.insertToTable('API', '', api, mal))

        elif (mal):  # update malicious api
            db.updateToTable('API', id=a[0], mal_cnt=a[1] + 1)
            entry.addappToApiRelation(a[0])

        elif (not mal):  # update benign api
            db.updateToTable('API', id=a[0], ben_cnt=a[1] + 1)
            entry.addappToApiRelation(a[0])

    # insert permissions
    for prm in uniquate_list(entry.getPermissions()):
        p = db.duplicatePermission(prm, mal)

        if (p[0] == -1):  # new PERMISSION
            entry.addappToPrmRelation(
                db.insertToTable('PERMISSION', '', prm, mal))

        elif (mal):  # update malicious permission
            db.updateToTable('PERMISSION', id=p[0], mal_cnt=p[1] + 1)
            entry.addappToPrmRelation(p[0])
        elif (not mal):  # update benign permission
            db.updateToTable('PERMISSION', id=p[0], ben_cnt=p[1] + 1)
            entry.addappToPrmRelation(p[0])

''' 
	@arg	: Instance containing relevant data for the analyzed apk
	@arg	: databese connector to sql locahost
    @ret	: None
'''
def uniquate_list(item):
    return list(set(item))



def execute_single(source, prepared):
	prepared.inform('Executing single mode..')
	return

# Filelist holds sublists of the input APK|VIR files to achieve multiprocessing
class File_List:
	def __init__(self, overalSize, cpu, fileList, start):
		print 'I am here in the new one'
		sublistSize = overalSize / cpu
		self.sublists = []
		for i in range(cpu):
			if (i != cpu-1):
				sublist = list(fileList[start: sublistSize*(i+1)])
				start = sublistSize * (i+1)
			else:
				sublist = list(fileList[start: overalSize])
			self.sublists.append(sublist)
			
	def getSublists(self):
		return self.sublists
