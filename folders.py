
from preparation import Preparation

class Folders:
	def __init__(self):
		self.prepared = Preparation()
		self.prepared.inform('foldres()')
		
	def execute(self):
		self.prepared.inform('folders executing..')
