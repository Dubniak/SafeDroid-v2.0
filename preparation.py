"""
Part of the SafeDroid v2.0 FrameWork.
Author : Arygriou Marios
Year : 2017
The framework is distributed under the GNU General Public License v3.0
"""

from optparse import OptionParser

import os
import sys
import re
import logging
from timeit import default_timer as timer
from time import gmtime, strftime
import logging.config

"""
class Preparation contains helping variables for the execution
"""
class Preparation:
	def __init__(self):
		# define default malicious and bening directories, absolute path
		self.malicious_directory = '/home/marios/Downloads/group2/malicious/'
		self.benign_direcory = '/home/marios/Downloads/group2/benign/'

		# csv directory, user needs to set up this directory to the absolute path of the installation folder +/data_pool
		self.csv_directory = '/home/marios/SafeDroid-v2.0/data_pool/'
		
		# execution modes
		option_0 = {'name': ('-l', '--log'), 
					'help': 'Log level {DEBUG, INFO, WARN, ERROR, CRITICAL}', 'nargs': 1}
		option_1 = {'name': ('-m', '--malicious-folder'),
					'help': 'Malicious input folder {ABSOLUTE PATH}', 'nargs': 1}
		option_2 = {'name': ('-b', '--benign-folder'),
					'help': 'Benign input folder {ABSOLUTE PATH}', 'nargs': 1}
		option_3 = {'name': ('-t', '--testing-mode'),
					'help': 'Testing mode {FOLDERS, SET, SINGLE}', 'nargs': 1}
		option_4 = {'name': ('-r', '--reset'),
					'help': 'Reset database schema', 'nargs': 0}
		option_5 = {'name': ('-R', '--Reset'),
					'help': 'Reset database schema and exit', 'nargs': 0}
		option_6 = {'name': ('-s', '--skip-analysis'),
					'help': 'Skip reversing apks and use database to get input', 'nargs': 0}
		self.options = [option_0, option_1, option_2, option_3, option_4, option_5, option_6]
		
		# Logger
		self.log = logging.getLogger('SafeDroid')
		self.log.setLevel(logging.CRITICAL)
		self.formatter = logging.Formatter('%(asctime)s - %(filename)s: '
									  '%(levelname)s: '
									  '%(funcName)s(): '
									  '%(lineno)d:\t'
									  '%(message)s')
		self.handler = logging.FileHandler('safedroid.log', mode='w')
		self.handler.setFormatter(self.formatter)
		self.log.addHandler(self.handler)

		self.debug_level = {0: 'NOTSET', 10: 'DEBUG', 20: 'INFO',
					   30: 'WARNING', 40: 'ERROR', 50: 'CRITICAL'}

		# File list
		self.file_list = []

		# feedback bar
		self.size = 0
		self.sizeCurrent = 0
		return
		
	def set_size(self, size):
		self.size = size
		
	def get_size(self):
		return self.size
		
	def append_file_list(self,path_to_apk):
		self.file_list.append(path_to_apk)
		
	def get_file_list(self):
		return self.file_list
		
	def get_malicous_directory(self):
		return self.malicious_directory 
		
	def get_benign_directory(self):
		return self.benign_direcory
		
	def set_malicious_directory(self, directory):
		self.malicious_directory = directory
		
	def set_benign_directory(self, directory):
		self.benign_directory = directory
		
	def get_csv_directory(self):
		return self.csv_directory
		
	def get_options(self):
		return self.options
		
	def set_log_level(self, level):
		self.log.setLevel(level)
		
	def write_log_info(self, message):
		self.log.info(message)
		
	def write_log_error(self, message):
		self.log.error(message)
		
	def write_log_critical(self, message):
		self.log.critical(message)
		
	def write_log_debug(self, message):
		self.log.debug(message)
		
	def get_log_level(self):
		return 'Logging level set to ' + \
                self.debug_level[self.log.getEffectiveLevel()]
	
	def set_parser_error(self, message):
		self.parser.error(message)
		
		
	def read_options(self,options):
		self.parser = OptionParser()
		for option in options:
			param = option['name']
			del option['name']
			self.parser.add_option(*param, **option)
		print 'marios'
		#print self.parser.parse_args()
		return self.parser.parse_args()
		
	def inform(self, string):
		print string
	
	def inform_about_starting_time(self):
		self.inform('Starting time: ' + strftime("%Y-%m-%d %H:%M:%S", gmtime()))
