
"""
Part of the SafeDroid v2.0 FrameWork.
Author : Arygriou Marios
Year : 2017
The framework is distributed under the GNU General Public License v3.0
"""
import vectors
from vectors import Applications , AppToApi, API
from feature_vectors import superFeatureVector 
import pandas as pd
import numpy as np
import os
from sklearn import preprocessing
import cPickle as pickle
from joblib import Parallel, delayed 
import multiprocessing
from data import Data, Config
from timeit import default_timer as timer
from sklearn.neighbors import KNeighborsClassifier, RadiusNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.ensemble import RandomForestClassifier, AdaBoostClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn import metrics
from sklearn.metrics import f1_score
import pylab as pl
from matplotlib.colors import ListedColormap
from sklearn import svm


def getFeatureVector(sd):
	return superFeatureVector(sd) 
	
def f1Score(y_true, y_pred):
	score = {}
	try:
		score['macro'] = f1_score(y_true, y_pred, average='macro')
		score['micro'] = f1_score(y_true, y_pred, average='micro')
		score['weighted'] = f1_score(y_true, y_pred, average='weighted')
	except UndefinedMetricWarning: #division by 0
		return dict(macro=0,micro=0,weighted=0)
	
	return score
	
def calculateValues(confusion, length):
	try:
		TP = confusion[1,1]/float(length)
		TN = confusion[0,0]/float(length)
		FP = confusion[0,1]/float(length)
		FN = confusion[1,0]/float(length)
		return dict(tp=TP , tn=TN, fp=FP, fn=FN)
	except:
		return [-1,-1,-1,-1]

def KNN(featureVector, sd , tune , ts):
	results = []
	_target_counter , _ratio_counter , i  = 0 , 0 , 0
	
	for matrix in featureVector: #len of feature vectors = number of threshold filters
		for vector in matrix: #len of matrix = number of samples defined by reduce size
			X = vector['vector']
			y = sd.target[_target_counter]
			X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=ts, random_state=4)
			try:
				knn = KNeighborsClassifier(n_neighbors=tune['n_neighbors'], weights=tune['weights'],algorithm = tune['algorithm'], n_jobs=multiprocessing.cpu_count())
				knn.fit(X_train,y_train)
				y_pred = knn.predict(X_test)
				accuracy = metrics.accuracy_score(y_test,y_pred)
				confusion = metrics.confusion_matrix(y_test,y_pred)
				fbk = calculateValues(metrics.confusion_matrix(y_test,y_pred), len(y_test))
				f1 = f1Score(y_test, y_pred)
				
				results.append(dict(accuracy=accuracy, supl_info = vector['info'], f1 = f1 , confusion_matrix = confusion , tune = tune , fbk = fbk, fv = X.shape[1]))
			except ValueError:
				continue
			_target_counter +=1 
		_target_counter = 0
		_ratio_counter +=1
	return results
	
def SupportVectorMachine(featureVector, sd, tune , ts): 
	results = []
	_target_counter , _ratio_counter , i  = 0 , 0 , 0
	
	for matrix in featureVector: #len of feature vectors = number of threshold filters
		for vector in matrix: #len of matrix = number of samples defined by reduce size
			X = vector['vector']
			y = sd.target[_target_counter]
			X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=ts, random_state=4)
			try:
				if tune['kernel'] is 'rbf':
					knn = svm.SVC(kernel=tune['kernel'], class_weight='balanced', gamma = tune['gamma'] , C = tune['C'])
				else:
					knn = svm.SVC(kernel=tune['kernel'], class_weight='balanced', C = tune['C'])
					
				
				knn.fit(X_train,y_train)
				y_pred = knn.predict(X_test)
				accuracy = metrics.accuracy_score(y_test,y_pred)
				confusion = metrics.confusion_matrix(y_test,y_pred)
				fbk = calculateValues(metrics.confusion_matrix(y_test,y_pred), len(y_test))
				f1 = f1Score(y_test, y_pred)
				results.append(dict(accuracy=accuracy, supl_info = vector['info'], f1 = f1 , confusion_matrix = confusion , tune = tune , fbk = fbk, fv = X.shape[1]))
			except ValueError:
				continue
				
			_target_counter +=1

		_target_counter = 0
		_ratio_counter += 1
		
	return results

def DTreeClassifier(featureVector, sd, tune, ts):
	results = []
	_target_counter , _ratio_counter , i  = 0 , 0 , 0
	for matrix in featureVector: 
		for vector in matrix: 
			X = vector['vector']
			y = sd.target[_target_counter]
			X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=ts, random_state=4)
			try:
				knn = DecisionTreeClassifier(min_weight_fraction_leaf=tune['min_weight_fraction_leaf'], class_weight=tune['class_weight'], min_samples_split=tune['min_samples_split'],max_depth=tune['max_depth'])
				knn.fit(X_train,y_train)
				y_pred = knn.predict(X_test)
				accuracy = metrics.accuracy_score(y_test,y_pred)
				confusion = metrics.confusion_matrix(y_test,y_pred)
				fbk = calculateValues(metrics.confusion_matrix(y_test,y_pred), len(y_test))
				f1 = f1Score(y_test, y_pred)
				
				results.append(dict(accuracy=accuracy, supl_info = vector['info'], f1 = f1 , confusion_matrix = confusion , tune = tune , fbk = fbk, fv = X.shape[1]))
			except ValueError, TypeError:
				continue
				
			_target_counter +=1

		_target_counter = 0
		_ratio_counter += 1
		
	return results

def RForestClassifier(featureVector, sd, tune ,ts):
	results = []
	_target_counter , _ratio_counter , i  = 0 , 0 , 0
	
	for matrix in featureVector: #len of feature vectors = number of threshold filters
		for vector in matrix: #len of matrix = number of samples defined by reduce size
			X = vector['vector']
			y = sd.target[_target_counter]
			X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=ts, random_state=4)
			try:
				knn = RandomForestClassifier(n_estimators=tune['n_estimators'], min_samples_split = tune['min_samples_split'], oob_score = tune['oob_score'], class_weight = tune['class_weight'], n_jobs=multiprocessing.cpu_count())
				knn.fit(X_train,y_train)
				y_pred = knn.predict(X_test)
				accuracy = metrics.accuracy_score(y_test,y_pred)
				confusion = metrics.confusion_matrix(y_test,y_pred)
				fbk = calculateValues(metrics.confusion_matrix(y_test,y_pred), len(y_test))
				f1 = f1Score(y_test, y_pred)
				
				results.append(dict(accuracy=accuracy, supl_info = vector['info'], f1 = f1 , confusion_matrix = confusion , tune = tune , fbk = fbk, fv = X.shape[1]))
			except ValueError:
				continue
				
			_target_counter +=1

		_target_counter = 0
		_ratio_counter += 1
		
	return results
	
def MLP(featureVector, sd, tune ,ts):
	results = []
	_target_counter = 0
	_ratio_counter = 0
	config = Config('model_training.config')
	i=0

	
	for matrix in featureVector:
		for vector in matrix: 
			X = vector['vector']
			y = sd.target[_target_counter]
			
			X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=ts, random_state=4)
			try:
				if tune['solver'] is 'sgd':
					knn = MLPClassifier(solver=tune['solver'], activation=tune['activation'],learning_rate=tune['learning_rate'])
				else:
					knn = MLPClassifier(solver=tune['solver'], activation=tune['activation'])
				knn.fit(X_train,y_train)
				y_pred = knn.predict(X_test)
				accuracy = metrics.accuracy_score(y_test,y_pred)
				confusion = metrics.confusion_matrix(y_test,y_pred)
				fbk = calculateValues(metrics.confusion_matrix(y_test,y_pred), len(y_test))
				f1 = f1Score(y_test, y_pred)
				
				results.append(dict(accuracy=accuracy, supl_info = vector['info'], f1 = f1 , confusion_matrix = confusion , tune = tune , fbk = fbk, fv = X.shape[1]))
			except ValueError:
				continue
				
			_target_counter +=1

		_target_counter = 0
		_ratio_counter += 1
		
	return results

def AdaBoost(featureVector, sd, tune,ts):
	results = []
	_target_counter = 0
	_ratio_counter = 0
	config = Config('model_training.config')
	i=0
	
	for matrix in featureVector:
		for vector in matrix: 
			X = vector['vector']
			y = sd.target[_target_counter]
			X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=ts, random_state=4)
			try:
				knn = AdaBoostClassifier(n_estimators=tune['n_estimators'], algorithm = tune['algorithm'])
				knn.fit(X_train,y_train)
				y_pred = knn.predict(X_test)
				accuracy = metrics.accuracy_score(y_test,y_pred)
				confusion = metrics.confusion_matrix(y_test,y_pred)
				fbk = calculateValues(metrics.confusion_matrix(y_test,y_pred), len(y_test))
				f1 = f1Score(y_test, y_pred)
		
				results.append(dict(accuracy=accuracy, supl_info = vector['info'], f1 = f1 , confusion_matrix = confusion , tune = tune , fbk = fbk,fv = X.shape[1]))
			except ValueError:
				continue
				
			_target_counter +=1

		_target_counter = 0
		_ratio_counter += 1
		
	return results
	
def trainModel(featureVector, sd , classifier, tune):
	results = {}
	_dispatcher = {'KNeighbor' : KNN, 											#ok
					'SVM': SupportVectorMachine, 								#ok
					'DTree':DTreeClassifier,									#ok
					'RForest':RForestClassifier,								#ok
					'MLP':MLP,
					'ADA':AdaBoost			
					}
	
	return _dispatcher[classifier](featureVector,sd,tune,0.4)
