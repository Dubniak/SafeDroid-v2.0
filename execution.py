from preparation import Preparation
#from modes import Dispatcher
from servant import Servant
import multiprocessing
from multiprocessing import Pool

'''
Contains all different modes of execution
'''

class Directory:
	def __init__(self):
		#self.prepared = Preparation()
		#self.prepared.inform('folders()')
		self.servant = Servant()
		return
		
	def execute(self, prepared):
		#self.prepared.inform('folders executing..')
		prepared.set_size(self.servant.get_directory_size_bytes(prepared.get_malicous_directory(), prepared) + self.servant.get_directory_size_bytes(prepared.get_benign_directory(), prepared))
		print 'Size is %s' %prepared.get_size()
		#size = getFolderSize(MAL_FOLDER) + getFolderSize(BEN_FOLDER)
		size_mal = 0
		size_ben = 0
		perv = 0
		number_of_files = 0
		from modes import Dispatcher
		#fl = Filelist(len(file_list), multiprocessing.cpu_count(), file_list, 0)
		fl = Dispatcher(len(prepared.get_file_list()), multiprocessing.cpu_count(), prepared.get_file_list(), 0)
		sub = fl.getSublists()
		pool = Pool()
		pool.map(reverseAnalysis, sub)
		pool.close()
		pool.join()

class Single:
	def __init__(self):
		print 'Single mode of execution'
		return
		
	def execute(self, prepared):
		#do stuff
		prepared.inform('Single mode executing..')
		return
		
	
