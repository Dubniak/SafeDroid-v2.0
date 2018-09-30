from execution import *


'''
Modes: determines the mode of execution, as selected by the user and executes
'''


class Execution_Mode:
	def __init__(self):
		self.directory = Directory()
		self.single = Single()
		self.dispatcher = {'FOLDERS':self.directory.execute,'SINGLE':self.single.execute}

		
	def dispatch(self, mode, prepared):
		return self.dispatcher[mode](prepared)
		
		
class Dispatcher:
	def __init__(self, overalSize, cpu, fileList, start):
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

