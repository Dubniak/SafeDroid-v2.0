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
from data import Data
from timeit import default_timer as timer
from joblib import Parallel, delayed

'''
			@var apisOfApps: list containing api calls of an application
			@var apiVector: list containing malicious filtered apis
			@ret : numpy.array in form of [0 0 1 0 ... 1] , length = length(apiVector)
'''


def createSubVector(apisOfApps, apiVector):

    tmp_vector = []
    common_api = apiVector.api.isin(apisOfApps.api)
    for item in common_api.iteritems():
        if item[1] == True:
            tmp_vector.append(1)
        else:
            tmp_vector.append(0)
    return np.array(tmp_vector)


def createFeatureVector(apisOfApps, apiVector):
    start = timer()
    vectors = []
    counter = 0
    for item in apisOfApps:
        dic = {}
        aoa = item['apisOfApps']
        length = len(aoa)
        print str(counter) + ': length = ' + str(length)
        features = []
        features = Parallel(n_jobs=5)(delayed(createSubVector)(
            aoa[index], apiVector) for index in range(0, length))
        dic['vector'] = np.array(features)
        dic['info'] = item['info']
        vectors.append(dic)
        counter += 1
    end = timer()
    return vectors


def superFeatureVector(sd):
    fv = []
    for vector in sd.apiVector:
        fv.append(createFeatureVector(sd.apisOfApps, vector))
    return fv
