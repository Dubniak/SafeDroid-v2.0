import os



class Servant:
	def __init__(self):
		return
		
	def get_directory_size_bytes(self, path, prepared):
		size = 0
		for f in os.listdir(path):
			size += os.stat(os.path.join(path, f)).st_size
			prepared.append_file_list(os.path.join(path, f))
			#file_list.append(os.path.join(path, f))
		return size
		


