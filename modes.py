from folders import Folders

class Modes():
	def __init__(self):
		self.folders = Folders()
		self.dispatcher = {'FOLDERS':self.folders.execute}

		
	def dispatch(self, mode):
		return self.dispatcher[mode]()
