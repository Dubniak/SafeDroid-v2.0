"""
Part of the SafeDroid v2.0 FrameWork.
Author : Arygriou Marios
Year : 2018
The framework is distributed under the GNU General Public License v3.0
"""
from vectors import Applications, AppToApi, API
from config import Config
import pandas as pd
import numpy as np
import os
from sklearn import preprocessing
import cPickle as pickle
from joblib import Parallel, delayed
import multiprocessing
import collections


"""
	class Data represents database entries and correlations to dataframes. 
	Dataframes are attributes of the class and logic is applied to them at creation time.
"""
class Data:
    def __init__(self, dir_name):
        _columnNames = [['api', 'malicious', 'benign', 'ratio'],  # api
                        ['name', 'md5', 'isMalicious'],  # application
                        ['appid', 'apiid'],  # apptoapi
                        ['appid', 'prmid'],  # apptoprm
                        ['permission', 'malicious', 'benign', 'ratio']]  # permission

        _files = ['api.csv', 'applications.csv',
                  'apptoapi.csv', 'apptoprm.csv', 'permission.csv']

        ''' 	app , api , apptoapi hold the relative data extracted from the database
				apiVector holds the filtered apis with a malicious ratio above threshold
				apisOfApps holds the api calls of each of the apps found in the app matrix 
        '''
        self.config = Config('model_training.config')

        self.sizes = []
        self.app = self.init_app(os.path.join(
            os.getcwd(), dir_name, _files[1]), _columnNames[1])
        self.api = API(os.path.join(os.getcwd(), dir_name, _files[0]), _columnNames[0], [
                       self.app.getMaliciousSize(), self.app.getBenignSize()])
        self.apptoapi = self.init_apptoapi(os.path.join(
            os.getcwd(), dir_name, _files[2]), _columnNames[2])

        # apis after reduction
        self.apiVector = self.createApiVectors()
        # names of apis in apiVector
        self.feature_names = self.setFeatureNames()

        # create datasets with respect to inputs for config file
        # list of dicts, dict keys = ['data_sets'],['info']
        self.data_sets = self.formDataSets()

        self.target = self.setTargets()
        self.target_names = self.app.target_names

        # list of dicts, keys = 'apisOfApps','info'
        self.apisOfApps = self.apisOfAppListDF()
        return

    def createApiVectors(self):
        av = []
        for threshold in self.config.threshold():
            av.append(self.api.getFiltered(threshold=threshold))

        return av

    def addDataSetSizeInfo(self, mal_s, mal_r, ben_s, ben_r, overal_s, overal_r):
        return dict(mal_size=mal_s, mal_ratio=mal_r, ben_size=ben_s, ben_ratio=ben_r, overall_size=overal_s, overall_ratio=overal_r)

    def formDataSets(self):
        ds = []
        for reduction in self.config.reduce_size():
            new_overall_size = int(self.app.getOverallSize() * reduction)
            for malicious_perc in self.config.malicious_size():
                dic = {}
                if (int(new_overall_size * malicious_perc) > len(self.app.malicious)):
                    malicious_size = len(self.app.malicious)
                else:
                    malicious_size = int(new_overall_size * malicious_perc)

                benign_size = new_overall_size - malicious_size
                if (benign_size > len(self.app.benign)):
                    benign_size = len(self.app.benign)

                # create redused malicious set
                mask_malicious = np.random.choice([False, True], len(self.app.malicious), p=[
                                                  1-float(malicious_size)/len(self.app.malicious), float(malicious_size)/len(self.app.malicious)])
                malicious_set = self.app.malicious.iloc[mask_malicious]

                # create redused benign set
                mask_benign = np.random.choice([False, True], len(self.app.benign), p=[
                                               1-float(benign_size)/len(self.app.benign), float(benign_size)/len(self.app.benign)])
                benign_set = self.app.benign.iloc[mask_benign]

                # concatenate two sets and shuffle entries
                dic['data_set'] = pd.concat(
                    [malicious_set, benign_set], axis=0).sample(frac=1)
                dic['info'] = self.addDataSetSizeInfo(len(malicious_set), float(len(malicious_set))/(len(malicious_set)+len(benign_set)), len(
                    benign_set), 1-float(len(malicious_set))/(len(malicious_set)+len(benign_set)), len(malicious_set)+len(benign_set), reduction)

                # filter out possible duplicate data sets that will slow down the procedure
                if len(self.sizes) == 0:
                    self.sizes.append(dic['info'])
                    ds.append(dic)
                else:
                    for item in self.sizes:
                        if item == dic['info']:
                            print 'Same values already computed'
                        else:
                            ds.append(dic)
                            self.sizes.append(dic['info'])
                            break

        return ds

    def setTargets(self):
        t = []
        for entry in self.data_sets:
            ds = entry['data_set']
            t.append(np.array(ds.isMalicious))
        return t

    def setFeatureNames(self):
        fn = []
        for vector in self.apiVector:
            fn.append(np.array(vector.api))
        return fn

    def init_api(self, filepath, columnNames):
        api = API(filepath, columnNames)
        api.setRatio()
        return api

    def init_app(self, filepath, columnNames):
        app = Applications(filepath, columnNames)
        return app

    def init_apptoapi(self, filepath, columnNames):
        return AppToApi(filepath, columnNames)

    def extractApis(index, api, apptoapi):
        return api.loc[apptoapi[apptoapi.appid == index].apiid]

    def apisOfAppListDF(self):
        df = []
        for ds in self.data_sets:
            dic = {}
            matrix = ds['data_set']
            application = []
            length = len(matrix)
            print length
            for i in range(0, length):
                ID = matrix.index[i]
                application.append(
                    self.api._matrix.loc[self.apptoapi._matrix[self.apptoapi._matrix.appid == ID].apiid])
            dic['apisOfApps'] = application
            dic['info'] = ds['info']
            df.append(dic)
        return df
