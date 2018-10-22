"""
Part of the SafeDroid v2.0 FrameWork.
Author : Arygriou Marios
Year : 2018
The framework is distributed under the GNU General Public License v3.0
"""

import os
from sql_db import SafeDroidDB
import multiprocessing
from create_csv import createDir, createFile
from data import Data, Config
from feature_vectors import superFeatureVector


"""
class Servant contains both primary and secondary functions to support the execution
"""
class Servant:
	def __init__(self):
		return
		
	def get_directory_size_bytes(self, path, prepared):
		size = 0
		for f in os.listdir(path):
			size += os.stat(os.path.join(path, f)).st_size
			prepared.append_file_list(os.path.join(path, f))
		return size
		
	
	"""
	@arg	:Prepared instance
	@ret	:none
	@use	:deletes tables from the database
	"""	
	def reset_database(self, prepared):
		t = SafeDroidDB(False)
		t.dropTable('APPLICATIONS')
		t.dropTable('API')
		t.dropTable('APPtoAPI')
		t.dropTable('PERMISSION')
		t.dropTable('APPtoPRM')
		prepared.write_log_info('Resetting Database..Success')
		
	def draw_progress_bar(percent, barLen=50):
		sys.stdout.write("\r")
		progress = ""
		for i in range(barLen):
			if i < int(barLen * percent):
				progress += "="
			else:
				progress += " "
			sys.stdout.write("[ %s ] %.2f%%" % (progress, percent * 100))
			sys.stdout.flush()
			
	def get_folder_size(path):
		size = 0
		for f in os.listdir(path):
			size += os.stat(os.path.join(path, f)).st_size
			file_list.append(os.path.join(path, f))
		return size
	
	"""
	@arg	:none
	@ret	:none
	@use	:Spawn 5 processes (or multiprocessing.cpu_count() if the multiprocessing.cpu_count()<6) 
				to create csv files containing data from the database
	"""	
	def extractCSV(self):
		createDir()
		tables = ('APPLICATIONS', 'API', 'PERMISSION', 'APPtoPRM', 'APPtoAPI')
		pool = multiprocessing.Pool(5 if multiprocessing.cpu_count()>5 else multiprocessing.cpu_count())
		pool.map(createFile, tables)
		pool.close()
		pool.join()
		
	def getInputData(self,prepared):
		sd = Data(prepared.get_csv_directory())
		feature_vector = superFeatureVector(sd)
		return sd, feature_vector


