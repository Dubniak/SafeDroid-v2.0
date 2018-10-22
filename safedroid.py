"""
Part of the SafeDroid v2.0 FrameWork.
Author : Arygriou Marios
Year : 2018
The framework is distributed under the GNU General Public License v3.0
"""

from androwarn_reverse import getAPIfromPkg
from optparse import OptionParser

import os
import sys
import re
import logging
from timeit import default_timer as timer
import logging.config
from time import gmtime, strftime
import shlex
import subprocess
import pickle

# SafeDroid imports

import vectors
from vectors import Applications, AppToApi, API
from sql_db import SafeDroidDB #imported in servant
from Algorithm_Comparison import Tune, Model
from trainer import trainModel
from Report import Report
from preparation import Preparation
from execution_choices import *
from servant import Servant

# testing deprecation ignoring
import warnings


def calculatePercentage(part, whole):
    return part/whole



def specified_set(db):
    # testing specific APKs

    viruses = []  # path to singel malware files, for testing
    for v in viruses:
        data = getAPIfromPkg(v)
        entry = parse_data(data, False)
        insertToDB(entry, db)
        db.insertRelation(entry.getappId(), uniquate_list(
            entry.getappToApiRelation()))
        db.insertAppToPrmRelation(
            entry.getappId(), uniquate_list(entry.getappToPrmRelation()))


def single_APK(db):
    # testing one APK

    # insert path to single malware here
    data = getAPIfromPkg('path_to_malware')
    entry = parse_data(data, True)
    insertToDB(entry, db)
    db.insertRelation(entry.getappId(), uniquate_list(
        entry.getappToApiRelation()))
    db.insertAppToPrmRelation(
        entry.getappId(), uniquate_list(entry.getappToPrmRelation()))


def main(options, arguments, prepared, servant):
        # set log level
    if (options.log != None):
        try:
            print options.log
            prepared.set_log_level(options.log)
            print prepared.get_log_level()
        except:
            prepared.set_parser_error("Please specify a valid log level")
    else:
        prepared.inform(prepared.get_log_level())

    # Reset Database & Exit
    if (options.Reset != None and 'yes' in raw_input('Reset database? ')):
		servant.reset_database(prepared)
		exit(1)

    # Malicious Folder
    if (options.malicious_folder != None):
        found_flag = False
        try:
            for f in os.listdir(options.malicious_folder):
                if '.vir' in f or '.apk' in f:
                    prepared.set_malicious_directory(options.malicious_folder)
                    found_flag = True
                    prepared.inform('Malicious folder set to ' +
                                    options.malicious_folder)
                    prepared.write_log_info(
                        'Malicious folder set to %s' % options.malicious_folder)
                    break
            if found_flag is not True:
                prepared.inform('Malicious folder set to default')
                prepared.write_log_error(
                    "Path %s does not contain '.apk' or '.vir' files" % options.malicious_folder)
        except Exception, err:
            prepared.set_parser_error("Malicious folder path is not valid.")
    else:
        prepared.inform("Malicious folder set to default")
        if not os.path.exists(prepared.get_malicous_directory()):
            prepared.write_log_critical(
                "%s doesn't exist" % prepared.get_malicous_directory())
            exit()
        prepared.write_log_info(
            'Malicious folder set to default %s' % prepared.get_malicous_directory())

    # Benign Foler
    if (options.benign_folder != None):
        found_flag = False
        try:
			for f in os.listdir(options.benign_folder):
				if '.vir' in f or '.apk' in f:
					prepared.set_benign_directory(options.benign_folder)
					found_flag = True
					prepared.inform('Benign folder set to ' + options.benign_folder)
					prepared.write_log_info(
						'Benign folder set to %s' % options.benign_folder)
					break
				if found_flag is not True:
					prepared.write_log_error(
						"Path %s does not contain '.apk' or '.vir' files" % options.benign_folder)
				print "Benign folder set to default"
        except Exception, err:
			prepared.set_parser_error("Benign folder path is not valid.")

    else:
        if not os.path.exists(prepared.get_benign_directory()):
            prepared.write_log_critical(
                "%s doesn't exist" % prepared.get_benign_directory())
            exit()
        print "Benign folder set to default"
        prepared.write_log_info(
            "Benign folder set to default %s" % prepared.get_benign_directory())

    # reset Database
    if (options.reset != None):
		servant.reset_database(prepared)
		prepared.inform("Resetting databse......[OK]")
		return

    # mode of execution
    if (options.testing_mode != None):
		print '1'
		#execution = Execution_Mode()
		print '2'
		start = timer()
		prepared.inform('Mode : ' + str(options.testing_mode))
		prepared.inform_about_starting_time()
		db = SafeDroidDB(True)
		
		execution_dispatch(options.testing_mode, prepared)
		'''
        if (options.testing_mode == str(1) or 'FOLDERS' in options.testing_mode): DONE
			
            folders(db)
        elif (options.testing_mode == str(2) or 'SET' in options.testing_mode):
            specified_set(db)
        elif (options.testing_mode == str(3) or 'SINGLE' in options.testing_mode):
            single_APK(db)
        end = timer()
		'''


    

def getInputData(prepared):
    sd = Data(prepared.get_csv_directory())
    feature_vector = superFeatureVector(sd)
    return sd, feature_vector


def getMostAccurateModel(results):  # 1
    max = -1
    index = 0
    i = 0
    model_name = ''
    for clsf, result in results.iteritems():
        for trial in result:
            if trial['accuracy'] > max:
                max = trial['accuracy']
                index = i
                model_name = clsf
            i += 1
        i = 0
    return model_name, index


'''
    # testing deprecation
    # with warnings.catch_warnings():
    #	warnings.simplefilter("ignore")
    #	Instance.fxn()
    parser = OptionParser()
    for option in options:
        param = option['name']
        del option['name']
        parser.add_option(*param, **option)
    start = timer()
    options, arguments = parser.parse_args()
    main(options, arguments)

'''

if __name__ == "__main__":
    prepared = Preparation()
    servant = Servant()
    opt = prepared.get_options()
    options, args = prepared.read_options(opt)
    start = timer()
    main(options, args, prepared, servant)

    #exit()
    end_analysis = timer()

    servant.extractCSV()

    start_fv = timer()
    data_set, feature_vector = servant.getInputData(prepared)
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
        clsf_models[model.getClassifier()] = trainModel(
            feature_vector, data_set, model.getClassifier(), model.getTune())
    decision = getMostAccurateModel(clsf_models)
    end_train = timer()

    best = clsf_models[decision[0]][decision[1]]

    tune.show_confusion_matrix(best['confusion_matrix'])
    end = timer()

    # produce Report
    global size
    report = Report("{0:.2f}".format(end-start), "{0:.2f}".format(end_analysis-start), "{0:.2f}".format(end_fv-start_fv), "{0:.2f}".format(end_tune-start_tune),
                    "{0:.2f}".format(end_train-start_train), prepared.get_benign_directory(), prepared.get_malicous_directory(), prepared.get_size())
    report.setAccuracy(best['accuracy'])
    report.setClassifier(decision[0])
    report.setF1(best['f1'])
    report.setConfusion(best['confusion_matrix'])
    report.setFVsize(best['fv'])
    report.saveReport()
