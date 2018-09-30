import os
from sql_db import SafeDroidDB



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
		
	def reverseAnalysis(self, sources, prepared):
		db = SafeDroidDB(False)
		for f in sources:
			mal = 0
			log.info('Application examined path: %s' % f)
			if (MAL_FOLDER in f):
				mal = 1
			try:
				data = getAPIfromPkg(f)
				entry = parse_data(data, mal)
				if db.exists('APPLICATIONS', entry.getMD5(), entry.getName()):
					continue
				insertToDB(entry, db)
				db.insertRelation(entry.getappId(), uniquate_list(entry.getappToApiRelation()))
				db.insertAppToPrmRelation(entry.getappId(), uniquate_list(entry.getappToPrmRelation()))
			except Exception, err:
				prepared.write_log_critical('%s failed' % f)
				prepared.write_log_critical(err)
				pass

		


