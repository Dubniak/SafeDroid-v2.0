"""
Part of the SafeDroid v2.0 FrameWork.
Author : Arygriou Marios
Year : 2017
The framework is distributed under the GNU General Public License v3.0
"""

from androwarn_reverse import getAPIfromPkg
from optparse import OptionParser

import os , sys, re , logging
from timeit import default_timer as timer
import logging.config
import multiprocessing
from multiprocessing import Pool
from time import gmtime, strftime
import shlex, subprocess
import pickle

#SafeDroid imports
from create_csv import createDir,createFile
import vectors
from vectors import Applications , AppToApi, API
from feature_vectors import superFeatureVector
from data import Data, Config
from sql_db import SafeDroidDB
from Algorithm_Comparison import Tune, Model
from trainer import trainModel
from Report import Report


#
MAL_FOLDER = ''
BEN_FOLDER = ''

#csv directory, user needs to set up this directory to the absolute path of the installation folder +/data_pool
_directory_csv = ''


# cmd input options
option_0 = {'name' : ('-l', '--log'),'help' : 'Log level {DEBUG, INFO, WARN, ERROR, CRITICAL}', 'nargs' : 1}
option_1 = {'name' : ('-m', '--malicious-folder'), 'help' : 'Malicious input folder {ABSOLUTE PATH}', 'nargs' : 1}
option_2 = {'name' : ('-b', '--benign-folder'), 'help' : 'Benign input folder {ABSOLUTE PATH}', 'nargs' : 1}
option_3 = {'name' : ('-t', '--testing-mode'), 'help' : 'Testing mode {FOLDERS, SET, SINGLE}', 'nargs' : 1}
option_4 = {'name' : ('-r', '--reset'), 'help': 'Reset database schema', 'nargs' : 0}
option_5 = {'name' : ('-R', '--Reset'), 'help': 'Reset database schema and exit', 'nargs' : 0}
options = [option_0 , option_1, option_2, option_3, option_4, option_5]

# Logger
log = logging.getLogger('SafeDroid')
log.setLevel(logging.CRITICAL)
formatter = logging.Formatter('%(asctime)s - %(filename)s: '    
                                '%(levelname)s: '
                                '%(funcName)s(): '
                                '%(lineno)d:\t'
                                '%(message)s')
handler = logging.FileHandler('safedroid.log',mode='w')
handler.setFormatter(formatter)
log.addHandler(handler)

debug_level= {0 : 'NOTSET', 10: 'DEBUG', 20: 'INFO', 30: 'WARNING', 40: 'ERROR', 50: 'CRITICAL'}

# File list
file_list = []

#feedback bar
size = 0
sizeCurrent = 0


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
    
    def addApi(self,a):
        self.api.append(a)
        
    def addPermission(self,p):
        self.permission.append(p)
        
    def addappToApiRelation(self, p):
        self.appToApiRelation.append(p)
        
    def addappToPrmRelation(self,p):
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
            print '\t' + str(i) + '.' +  a
            i = i + 1
        print 'permissions : '
        for p in self.permission:
            print '\t' + p 
        print 'receiver : '
        for r in self.receiver:
            print '\t' + r 
        if self.isMalicious:
            print '\tMalicious application'

def insertToDB(entry, db):
    ''' @arg : entry holds all values for an apk , db connects to sql locahost 
        @ret : None
    '''

    mal = entry.getMalicious()
    
    #set entry's api id alongside insertion
    entry.setappId(db.insertToTable('APPLICATIONS', entry.getMD5(), entry.getName(), mal))
    
    apis = entry.getAPIlist()
    i = 0
    
    #insert API
    dist_api = uniquate_list(entry.getAPIlist())
    
    for api in dist_api: 
        
        a = db.duplicateApi('API', api, mal)
       
        if (a[0] == -1): #new API
            entry.addappToApiRelation(db.insertToTable('API', '', api, mal))
            
        elif (mal): #update malicious api
            db.updateToTable('API', id = a[0] ,mal_cnt = a[1] + 1)
            entry.addappToApiRelation(a[0])
            
        elif (not mal): #update benign api
            db.updateToTable('API', id = a[0], ben_cnt = a[1] + 1)
            entry.addappToApiRelation(a[0])
            
    #insert permissions 
    for prm in uniquate_list(entry.getPermissions()):
        p = db.duplicatePermission(prm, mal)
        
        if (p[0] == -1): #new PERMISSION
            entry.addappToPrmRelation(db.insertToTable('PERMISSION','',prm,mal))
            
        elif (mal): #update malicious permission
            db.updateToTable('PERMISSION', id=p[0], mal_cnt = p[1] + 1)
            entry.addappToPrmRelation(p[0])
        elif (not mal): #update benign permission
            db.updateToTable('PERMISSION', id=p[0], ben_cnt = p[1] + 1)
            entry.addappToPrmRelation(p[0])
    
def uniquate_list(item):
    return list(set(item))

def parse_data(data, isMalicious):
    i=0 #generic counter, use at will
    inst = Instance()
    flag = False
    if data :
                    for item in data :
                            
                            for category, element_tuple in item.iteritems() :
                                    for name,content in element_tuple :
                                            if content and isinstance(name,str) :
                                                    for element in content :
                                                            if (name is 'activities' and not flag):
                                                                    inst.setName('.'.join(element.split('.')[:-1])[:100])
                                                                    flag = True
                                                            if (name is 'fingerprint' and 'MD5' in element ): #MD5
                                                                    inst.setMD5(element[5:])                                                                    
                                                            if (name is 'permissions' ) : #permissions 
                                                                    inst.addPermission(element)
                                                                    i += 1
                                                            if (name is 'classes_list' or name is 'internal_classes_list' or name is 'external_classes_list' or name is 'internal_packages_list' or name is 'external_packages_list'): #API
                                                                    inst.addApi(element[:100])
                                                                    
                                                            
   
    log.info("%s has %d API and %d permissions" %( str(inst.getMD5()), len(inst.getAPIlist()), len(inst.getPermissions())))
    if isMalicious:
        inst.setMalicious()
    return inst


def resetDatabase():    
    t = SafeDroidDB(False)
    t.dropTable('APPLICATIONS')
    t.dropTable('API')
    t.dropTable('APPtoAPI')
    t.dropTable('PERMISSION')
    t.dropTable('APPtoPRM')
    log.info('Resetting Database..Success')

# Filelist holds sublists of the input APK|VIR files to achieve multiprocessing
class Filelist:
    def __init__(self,overalSize,cpu,fileList,start):
        sublistSize = overalSize / cpu
        self.sublists = []
        for i in range(cpu):
            if (i != cpu-1):
                sublist = list(fileList[start : sublistSize*(i+1)])
                start = sublistSize * (i+1)
            else:
                sublist = list(fileList[start : overalSize])
            self.sublists.append(sublist)
    
    def getSublists(self):
        return self.sublists
        

def drawProgressBar(percent, barLen = 50):
    sys.stdout.write("\r")
    progress = ""
    for i in range(barLen):
        if i < int(barLen * percent):
            progress += "="
        else:
            progress += " "
    sys.stdout.write("[ %s ] %.2f%%" % (progress, percent * 100))
    sys.stdout.flush()
    
def getFolderSize(path):
    size = 0
    for f in os.listdir(path):
        size += os.stat(os.path.join(path,f)).st_size
        file_list.append(os.path.join(path,f))
    return size 

def calculatePercentage(part, whole):
    return part/whole

def reverseAnalysis(sources):
    db = SafeDroidDB(False)
    for f in sources:
        mal = 0
        log.info('Application examined path: %s' %f)
        if (MAL_FOLDER in f):
		   mal = 1
        try:
            data = getAPIfromPkg(f)
            
            entry = parse_data(data,mal)
            if db.exists('APPLICATIONS',entry.getMD5(), entry.getName()):
			  continue
            insertToDB(entry,db)
            db.insertRelation(entry.getappId(),uniquate_list(entry.getappToApiRelation()))
            db.insertAppToPrmRelation(entry.getappId(),uniquate_list(entry.getappToPrmRelation()))
        except Exception,err:
		   log.critical('%s failed' %f)
		   log.critical(err)
		   pass


# Input files from malicious and benign fodlers
def folders(db):
    global size
    size = getFolderSize(MAL_FOLDER) + getFolderSize(BEN_FOLDER) 
    size_mal = 0
    size_ben = 0
    perv = 0 
    number_of_files = 0
    fl = Filelist(len(file_list),multiprocessing.cpu_count(),file_list,0)
    sub = fl.getSublists()
    pool = Pool()
    pool.map(reverseAnalysis,sub)
    pool.close()
    pool.join()
        

def specified_set(db):
    #testing specific APKs

    viruses = [] #path to singel malware files, for testing
    for v in viruses:
        data = getAPIfromPkg(v)
        entry = parse_data(data,False)
        insertToDB(entry,db)
        db.insertRelation(entry.getappId(),uniquate_list(entry.getappToApiRelation()))
        db.insertAppToPrmRelation(entry.getappId(),uniquate_list(entry.getappToPrmRelation()))

def single_APK(db):
    #testing one APK
    
    data = getAPIfromPkg(#path_to_malware#)
    entry = parse_data(data,True)
    insertToDB(entry,db)
    db.insertRelation(entry.getappId(),uniquate_list(entry.getappToApiRelation()))
    db.insertAppToPrmRelation(entry.getappId(),uniquate_list(entry.getappToPrmRelation()))
    

def main(options, arguments):
	# set log level        
	if (options.log != None):
		try:
			log.setLevel(options.log)
			print 'Logging level set to ' + debug_level[log.getEffectiveLevel()]
		except:
			parser.error("Please specify a valid log level")
			
	else :
		print 'Logging level auto set to ' + debug_level[log.getEffectiveLevel()]

	# Reset Database & Exit
        if (options.Reset != None):
            if ('yes' in raw_input('Reset database? ')):
                resetDatabase()
            exit(1)
        
        # Malicious Folder
	if (options.malicious_folder != None):
                found_flag = False
                global MAL_FOLDER
		try:
			for f in os.listdir(options.malicious_folder):
				if '.vir' in f or '.apk' in f:
					MAL_FOLDER = options.malicious_folder
					found_flag = True
					print 'Malicious folder set to ' + options.malicious_folder
					log.info('Malicious folder set to %s' %options.malicious_folder)
					break 
                        if  found_flag is not True :
                                log.error("Path %s does not contain '.apk' or '.vir' files" %options.malicious_folder)
                                print "Malicious folder set to default"
		except Exception,err:
			parser.error("Malicious folder path is not valid.")
        else :
            
            print "Malicious folder set to default"
	    if not os.path.exists(MAL_FOLDER):
		log.critical("%s doesn't exist" % MAL_FOLDER)
		exit()
            log.info ('Malicious folder set to default %s' % MAL_FOLDER)
	
	# Benign Foler
	if (options.benign_folder != None):
                found_flag = False
                global BEN_FOLDER
		try:
			for f in os.listdir(options.benign_folder):
				if '.vir' in f or '.apk' in f:
					BEN_FOLDER = options.benign_folder
					found_flag = True
					print 'Benign folder set to ' + options.benign_folder
					log.info('Benign folder set to %s' %options.benign_folder)
					break 
                        if  found_flag is not True :
                                log.error("Path %s does not contain '.apk' or '.vir' files" %options.benign_folder)
                                print "Benign folder set to default"
		except Exception,err:
			parser.error("Benign folder path is not valid.")
	
	
	else :
	    if not os.path.exists(BEN_FOLDER):
		log.critical("%s doesn't exist" %BEN_FOLDER)
		exit()
            print "Benign folder set to default"
            log.info ('Benign folder set to default %s' %BEN_FOLDER)
        
        # reset Database
        if (options.reset != None):
		   resetDatabase()
		   if ('yes' in raw_input('Reset database? ')):
			   print 'Resetting database..'
			   resetDatabase()
        
        # mode of execution
        if (options.testing_mode != None):
            start = timer()
            print 'Mode : ' + str(options.testing_mode)
            a = strftime("%Y-%m-%d %H:%M:%S", gmtime())
            print 'Starting time: ' + a
            db = SafeDroidDB(True)
            if (options.testing_mode == str(1) or 'FOLDERS' in options.testing_mode):
                folders(db)
            elif (options.testing_mode == str(2) or 'SET' in options.testing_mode):
                specified_set(db)
            elif (options.testing_mode == str(3) or 'SINGLE' in options.testing_mode):
                single_APK(db)
            end = timer()
                
def extractCSV():
	createDir()
	tables = ('APPLICATIONS', 'API', 'PERMISSION', 'APPtoPRM', 'APPtoAPI')
	pool = Pool(5)
	pool.map(createFile,tables)
	pool.close()
	pool.join()

def getInputData():
	sd = Data(_directory_csv)
	feature_vector = superFeatureVector(sd)
	return sd , feature_vector

def getMostAccurateModel(results):#1
		max = -1
		index = 0
		i = 0 
		model_name = ''
		for clsf , result in results.iteritems():
			for trial in result:
				if trial['accuracy'] > max:
					max  = trial['accuracy']
					index = i
					model_name = clsf
				i += 1
			i = 0
		return model_name , index


if __name__== "__main__":
	parser = OptionParser()
	for option in options:
		param = option['name']
		del option['name']
		parser.add_option(*param, **option)
	start = timer()
	options , arguments = parser.parse_args()
	main(options, arguments)
	end_analysis = timer()	
	
	extractCSV()
	
	start_fv = timer()
	data_set , feature_vector = getInputData()
	end_fv = timer()
	conf = 'model_training.config'
	start_tune = timer()
	tune = Tune(data_set, feature_vector, conf)
	tune.tuneClassifiers()
	tune.fineTuneClassifiers()
	end_tune = timer()
	
	
	start_train = timer()
	clsf_models = {}
	for model in tune.getModels():
		clsf_models[model.getClassifier()] = trainModel(feature_vector,data_set,model.getClassifier(),model.getTune())
	decision = getMostAccurateModel(clsf_models)
	end_train = timer()
	
	best = clsf_models[decision[0]][decision[1]]
	
	tune.show_confusion_matrix(best['confusion_matrix'])
	end = timer()
	
	#produce Report
	global size
	report = Report("{0:.2f}".format(end-start),"{0:.2f}".format(end_analysis-start), "{0:.2f}".format(end_fv-start_fv), "{0:.2f}".format(end_tune-start_tune),
				"{0:.2f}".format(end_train-start_train),BEN_FOLDER,MAL_FOLDER, size )
	report.setAccuracy(best['accuracy'])
	report.setClassifier(decision[0])
	report.setF1(best['f1'])
	report.setConfusion(best['confusion_matrix'])
	report.setFVsize(best['fv'])
	report.saveReport()
