"""
Part of the SafeDroid v2.0 FrameWork.
Author : Arygriou Marios
Year : 2017
The framework is distributed under the GNU General Public License v3.0
"""
import pandas as pd
import numpy as np
import os
from sklearn import preprocessing
import cPickle as pickle


class API:
    ''' Create 3 DataFrames from api.csv : overall , malicious , benign
        @arg filepath : path csv file , string
        @arg column_names : names for columns , list

    '''

    def __init__(self, filepath, column_names, app_df_size):
        self._matrix = self.readData(filepath)
        self.setColumnNames(column_names)
        self.setRatio(app_df_size)
        self.feature_names = ['api', 'ratio']
        self.target = self.setTarget()
        self.target_ratio = self.setTargetRatio()
        return

    def setTarget(self):
        return np.array(self._matrix.api)

    def setTargetRatio(self):
        return np.array(self._matrix.ratio)

    def readData(self, filepath):
        return pd.read_csv(filepath, index_col=0, header=None)

    def getData(self):
        return self._matrix

    def calulateRatioApi(self, x):
        if (x.malicious == 0):
            return 0
        return float(x.malicious)/(x.malicious + x.benign)

    def calulateRatio(self, x, mal_apps, ben_apps):
        try:
            return float(x.malicious)/mal_apps - float(x.benign)/ben_apps
        except TypeError:
            print str(x.malicious), type(x.malicious)
            print str(mal_apps), type(mal_apps)
            print str(x.benign), type(x.benign)
            print str(ben_apps), type(ben_apps)
            exit()

    def trasformStringColumn(self, column=None):
        label_encoder = preprocessing.LabelEncoder()
        self._matrix['api'] = label_encoder.fit_transform(self._matrix['api'])

    def setRatio(self, size):
        self._matrix.ratio = self._matrix.apply(
            self.calulateRatio, axis=1, args=(size[0], size[1]))

    # sets column names
    def setColumnNames(self, names):
        if (len(names) != 0):
            try:
                self._matrix.columns = names
            except Exception:
                print Exception
        return

    # return dataframe filtered by ratio
    def getFiltered(self, threshold=None):
        if (threshold != None):
            return self._matrix[self._matrix.ratio >= threshold]
        return self._matrix[self._matrix.ratio >= 0.30]
        # return self._matrix[self._matrix.ratio >= threshold ] if threshold is not None else self._matrix[self._matrix.ratio >= 0.30 ]

    def splitSample(self, threshold=None):
        # thr = threshold == None ? 0.6 : threshold
        thr = threshold if threshold is not None else 0.6

    def getSubSet(self, indexes):
        '''@ attr indexes : the indexes of the subset
           @ ret : the subset
        '''
        return self._matrix.loc[indexes]

    def printSpecific(self, index):
        print self._matrix[self._matrix.index == index]


class Applications:
    def __init__(self, filepath, column_names):
        self._matrix = self.readData(filepath)
        self.setColumnNames(column_names)
        self.feature_names = ['application', 'isMalicious']
        self.target_names = np.array(['benign', 'malicious'])
        self.target = self.setTarget()

        # define Dataframes malicious, benign
        self.malicious = self._matrix[self._matrix.isMalicious == 1]
        self.benign = self._matrix[self._matrix.isMalicious == 0]
        return

    def readData(self, filepath):
        return pd.read_csv(filepath, index_col=0, header=None)

    def setTarget(self):
        return np.array(self._matrix.isMalicious)

    def setColumnNames(self, column_names):
        if len(column_names) != 0:
            try:
                self._matrix.columns = column_names
            except Exception:
                print Exception
        return

    def getData(self):
        return self._matrix

    def getMalicious(self):
        return self.malicious

    def getBenign(self):
        return self.benign

    def getMaliciousSize(self):
        return len(self._matrix[self._matrix['isMalicious'] == 1])

    def getBenignSize(self):
        return len(self._matrix[self._matrix['isMalicious'] == 0])

    def getOverallSize(self):
        return len(self._matrix)

    def getSubSet(self, indexes):
        '''@ attr indexes : the indexes of the subset
           @ ret : the subset
        '''
        return self._matrix.loc[indexes]

    def printSpecific(self, index):
        print self._matrix[self._matrix.index == index]


class Permissions:
    def __init__(self, filepath, column_names):
        self._matrix = self.readData(filepath)
        self.setColumnNames(column_names)
        self.setRatio()
        return

    def readData(self, filepath):
        return pd.read_csv(filepath, index_col=0, header=None)

    def setColumnNames(self, column_names):
        if len(column_names) != 0:
            try:
                self._matrix.columns = column_names
            except Exception:
                print Exception
        return

    def setRatio(self):
        self._matrix.ratio = self._matrix.apply(self.calulateRatio, axis=1)
        return

    def calulateRatio(self, x):
        return 0 if x.malicious == 0 else float(x.malicious)/(x.malicious + x.benign)


class AppToApi:
    def __init__(self, filepath, column_names):
        self._matrix = self.readData(filepath)
        self.setColumnNames(column_names)
        self.feature_names = ['application', 'api']
        #self.data = self.setData()
        return

    def readData(self, filepath):
        return pd.read_csv(filepath,  header=None)

    def setData(self):
        for i in range(0, len(self._matrix.index)):
            # do stuff
            return

    def setColumnNames(self, column_names):
        if len(column_names) != 0:
            try:
                self._matrix.columns = column_names
            except Exception:
                print Exception
        return

    def getAppId(self, apiId):
        ''' @attr apiId to search
                Find out which Applications use the specified API
            @ret  pandas.core.series.Series object holding appIds 
        '''
        return self._matrix[self._matrix.apiid == apiId].appid

    def getApiId(self, appId):
        ''' @attr appId to search
                Find out which APIs are used by a specific Application
            @ret  pandas.core.series.Series object holding apiIds 
        '''
        return self._matrix[self._matrix.appid == appId].apiid
