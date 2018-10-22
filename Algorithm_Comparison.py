"""
Part of the SafeDroid v2.0 FrameWork.
Author : Arygriou Marios
Year : 2017
The framework is distributed under the GNU General Public License v3.0
"""

import pickle
import numpy as np
import pandas as pd
import multiprocessing
from itertools import cycle
from scipy import interp
import warnings
from timeit import default_timer as timer
import operator
import logging
from time import gmtime, strftime
import os

import matplotlib.pyplot as plt

import matplotlib.patches as mpatches
from matplotlib import style

from sklearn.gaussian_process import GaussianProcessClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.gaussian_process.kernels import RBF
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn import svm, preprocessing, metrics, model_selection
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis
from sklearn.naive_bayes import GaussianNB
from sklearn.multiclass import OneVsRestClassifier
from sklearn.svm import SVC
from sklearn.metrics import roc_curve, auc, classification_report
from sklearn.model_selection import learning_curve, ShuffleSplit, GridSearchCV
from sklearn.ensemble import RandomForestClassifier, AdaBoostClassifier
from data import Config

plt.switch_backend('TKagg')  # change matplotlib backend kernel
warnings.filterwarnings('ignore')  # do not print depricasion warnings


class Model:
    def __init__(self, clsf_name, tune, acc=0.0, ber=None, cnv=None, dss=0, acc_cv=0.0, lmt=None):
        self.classifier = clsf_name
        self.tune = tune
        self.bias_error = ber
        self.converging = cnv
        self.dataSetSize = dss
        self.accuracy_pure = acc
        self.accuracy_cv = acc_cv
        self.passLimit = lmt

    def setPassLimit(self, lmt):
        self.passLimit = lmt

    def setConvergence(self, cnv=True):
        self.converging = cnv

    def setBiasError(self, ber=False):
        self.bias_error = ber

    def setDataSetSize(self, dss):
        self.dataSetSize = dss

    def setAccuracy(self, acc):
        self.accuracy_pure = acc

    def setAccuracyCV(self, acc):
        self.accuracy_cv = acc

    def setTune(self, tune):
        self.tune = tune

    def getConvergence(self):
        return self.converging

    def getTune(self):
        return self.tune

    def getClassifier(self):
        return self.classifier

    def getDataSetSize(self):
        return self.dataSetSize

    def getAccuracy(self):
        return self.accuracy_pure

    def getAccuracyCV(self):
        return self.accuracy_cv

    def getBiasError(self):
        return self.bias_error

    def getPassLimit(self):
        return self.passLimit


class Tune:
    def __init__(self, dataset, feature_vector, conf):
        self.log = logging.getLogger('SafeDroid.Tuning')
        self.sd = dataset
        self.fv = feature_vector
        self.maxi, self.maxj = self.getMaxDataSetSize(self.fv)
        self.models = []
        self.config = Config(conf)

    def getModels(self):
        return self.models

    def fineTuneClassifiers(self):
        for model in self.models:
            self.Learning_Curve_Plot(self.fv[self.maxi][self.maxj]['vector'], self.sd.target[self.maxj],
                                     model, display=self.config.display_plots(), filename=self.config.plot_to_file())
            self.Validation_Curve(self.fv[self.maxi][self.maxj]['vector'], self.sd.target[self.maxj],
                                  model, display=self.config.display_plots(), filename=self.config.plot_to_file())
            if self.config.display_plots() or self.config.plot_to_file():
                self.ROC(self.fv[self.maxi][self.maxj]
                         ['vector'], self.sd.target[self.maxj], model)
        return

    def tuneClassifiers(self):
        results = self.parameter_estimation(
            self.fv[self.maxi][self.maxj]['vector'], self.sd.target[self.maxj], None)
        opt_clsf, tuning, acc = self.getBestClassifier(results)
        best_tune = self.formTuneDictionary()
        for k, v in tuning.iteritems():
            best_tune[k] = v
        self.models.append(Model(opt_clsf, best_tune, acc=acc,
                                 dss=self.fv[self.maxi][self.maxj]['vector'].shape[0]))

        # second classifier
        alter_clsf = self.Cross_Validation_Plot(
            self.fv[self.maxi][self.maxj]['vector'], self.sd.target[self.maxj], self.fv[self.maxi][self.maxj]['info'])
        alter_clsf_value = max(alter_clsf.iteritems(), key=operator.itemgetter(1))[
            0]  # fetch name

        if alter_clsf_value is opt_clsf:
            print 'Reached on agreement for Optimum Classifier'
        else:
            result = self.parameter_estimation(
                self.fv[self.maxi][self.maxj]['vector'], self.sd.target[self.maxj], alter_clsf_value)
            best_tune = self.formTuneDictionary()
            for k, v in result[alter_clsf_value][-1]['tune'].iteritems():
                best_tune[k] = v
            self.models.append(Model(alter_clsf_value, best_tune, acc=result[alter_clsf_value][2][
                               result[alter_clsf_value][0]['score']], dss=self.fv[self.maxi][self.maxj]['vector'].shape[0]))
        return

    def Validation_Curve(self, X, y, model, display=False, filename=None):
        """
        Plot the influence of a single hyperparameter on the training score and the 
        validation score to find out whether the estimator is overfitting or underfitting
         for some hyperparameter values.

        If the training score and the validation score are both low, the estimator 
        will be underfitting. If the training score is high and the validation score
        is low, the estimator is overfitting and otherwise it is working very well. 
        A low training score and a high validation score is usually not possible
        """
        from sklearn.model_selection import validation_curve
        classifier = model.getClassifier()
        if classifier is 'MLP':
            return
        tune = model.getTune()
        scoring = "accuracy"

        try:
            if classifier == 'KNeighbor':
                param_range = np.array(
                    filter(lambda x: x % 2 != 0, list(range(4, 30))))
                param_name = "n_neighbors"
                xtitle = 'neighbors'
                train_scores, test_scores = validation_curve(KNeighborsClassifier(
                    weights=tune['weights'], algorithm=tune['algorithm']), X, y, param_name=param_name, param_range=param_range, cv=self.config.cv(), scoring=scoring, n_jobs=multiprocessing.cpu_count())
            elif classifier == 'ADA':
                param_range = np.array(
                    filter(lambda x: x % 2 != 0, list(range(4, 30))))
                param_name = 'n_estimators'
                xtitle = 'estimators'
                train_scores, test_scores = validation_curve(AdaBoostClassifier(
                    algorithm=tune['algorithm']), X, y, param_name=param_name, param_range=param_range, cv=self.config.cv(), scoring=scoring, n_jobs=multiprocessing.cpu_count())
            elif classifier == 'SVM':
                param_range = np.logspace(-6, -1, 5)
                param_name = 'gamma'
                xtitle = "$\gamma$"
                train_scores, test_scores = validation_curve(SVC(kernel=tune['kernel'], C=tune['C']), X, y, param_name=param_name, param_range=param_range, cv=self.config.cv(
                ), scoring=scoring, n_jobs=multiprocessing.cpu_count())
            elif classifier == 'DTree':
                param_range = np.array(
                    filter(lambda x: x % 5 == 0, list(range(4, 50))))
                param_name = 'max_depth'
                xtitle = 'depth'
                train_scores, test_scores = validation_curve(DecisionTreeClassifier(
                    class_weight=tune['weights']), X, y, param_name=param_name, param_range=param_range, cv=self.config.cv(), scoring=scoring, n_jobs=multiprocessing.cpu_count())
            elif classifier == 'RForest':
                param_range = np.array(
                    filter(lambda x: x % 2 != 0, list(range(4, 30))))
                param_name = 'n_estimators'
                xtitle = 'estimators'
                train_scores, test_scores = validation_curve(RandomForestClassifier(min_samples_split=tune['min_samples_split'], oob_score=tune['oob_score'], class_weight=tune[
                                                             'class_weight']), X, y, param_name=param_name, param_range=param_range, cv=self.config.cv(), scoring=scoring, n_jobs=multiprocessing.cpu_count())

        except ValueError, err:
            self.log.error(
                "Cannot validate estimation graph for %s.\nReason:" % classifier)
            self.log.error(err)
            return
        train_scores_mean = np.mean(train_scores, axis=1)
        train_scores_std = np.std(train_scores, axis=1)
        test_scores_mean = np.mean(test_scores, axis=1)
        test_scores_std = np.std(test_scores, axis=1)

        if display or filename:
            self.plot_validation_curve(classifier, xtitle, "Score", param_range,
                                       train_scores_mean, train_scores_std, test_scores_std, test_scores_mean)
            if filename:
                plt.savefig(self.generateFilename('ValidationCurve'))
            if display:
                plt.show()

    def generateFilename(self, assosiate_name):
        if not os.path.exists('Plots'):
            os.mkdir('Plots')
        return os.path.join(os.path.join(os.getcwd(), 'Plots/'), assosiate_name+strftime("%d%m_%H%M%S", gmtime())+'.png')

    def plot_validation_curve(self, classifier, xtitle, ytitle, param_range, train_scores_mean, train_scores_std, test_scores_std, test_scores_mean):
        plt.title("Validation Curve of %s" % classifier)
        plt.xlabel(xtitle)
        plt.ylabel(ytitle)
        plt.ylim(0.0, 1.1)
        lw = 2
        plt.semilogx(param_range, train_scores_mean,
                     label="Training score", color="darkorange", lw=lw)
        plt.fill_between(param_range, train_scores_mean - train_scores_std,
                         train_scores_mean + train_scores_std, alpha=0.2, color="darkorange", lw=lw)
        plt.semilogx(param_range, test_scores_mean,
                     label="Cross-validation score", color="navy", lw=lw)
        plt.fill_between(param_range, test_scores_mean - test_scores_std,
                         test_scores_mean + test_scores_std, alpha=0.2, color="navy", lw=lw)
        plt.legend(loc="best")
        return plt

    def resetParameters(self, model, param_name, param_range, test_scores_mean):
        if np.max(test_scores_mean) > model.getAccuracy():
            tune = model.getTune()
            tune[param_name] = param_range[test_scores_mean.argmax()]
            model.setTune(tune)
            return True

        return False

    def Learning_Curve_Plot(self, X, y, model, display=False, filename=None):  # 1
        """
        find out how much we benefit from adding more training data and whether 
        the estimator suffers more from a variance error or a bias error.
        If both the validation score and the training score converge to a value 
        that is too low with increasing size of the training set, we will not benefit 
        much from more training data.

        """
        classifier = model.getClassifier()
        tune = model.getTune()
        _title = {'KNeighbor': "Learning Curve (K Nearest Neighbor)",
                  'SVM': "Learning Curve (Support Vector Machine, %s kernel%s " % (tune['kernel'], " ,$\gamma=%s$" % str(tune['gamma']) if tune['gamma'] is not None else ''),
                  'DTree': "Learning Curve (Decision Tree Classifier)",
                  'RForest': "Learning Curve (Random Forest Classifier)",
                  'MLP': "Learning Curve (Multi-Layer Perceptron Classifier)",
                  'ADA': "Learning Curve (Ada-Boost Classifier)"
                  }

        cv = ShuffleSplit(n_splits=self.config.cv(),
                          test_size=self.config.test_size(), random_state=0)

        try:
            if classifier is 'KNeighbor':
                train_sizes, train_scores, test_scores = learning_curve(KNeighborsClassifier(
                    n_neighbors=tune['n_neighbors'], weights=tune['weights'], algorithm=tune['algorithm']), X, y, cv=cv, n_jobs=multiprocessing.cpu_count(), train_sizes=np.linspace(.1, 1.0, 5))
            elif classifier is 'SVM':
                train_sizes, train_scores, test_scores = learning_curve(SVC(
                    kernel=tune['kernel'], C=tune['C'], gamma=tune['gamma']), X, y, cv=cv, n_jobs=multiprocessing.cpu_count(), train_sizes=np.linspace(.1, 1.0, 5))
            elif classifier is 'DTree':
                train_sizes, train_scores, test_scores = learning_curve(DecisionTreeClassifier(min_weight_fraction_leaf=tune['min_weight_fraction_leaf'], class_weight=tune[
                                                                        'class_weight'], min_samples_split=tune['min_samples_split']), X, y, cv=cv, n_jobs=multiprocessing.cpu_count(), train_sizes=np.linspace(.1, 1.0, 5))
            elif classifier is 'RForest':
                train_sizes, train_scores, test_scores = learning_curve(RandomForestClassifier(n_estimators=tune['n_estimators'], min_samples_split=tune['min_samples_split'], oob_score=tune[
                                                                        'oob_score'], class_weight=tune['class_weight']), X, y, cv=cv, n_jobs=multiprocessing.cpu_count(), train_sizes=np.linspace(.1, 1.0, 5))
            elif classifier is 'MLP':
                train_sizes, train_scores, test_scores = learning_curve(MLPClassifier(
                    solver=tune['solver'], activation=tune['activation']), X, y, cv=cv, n_jobs=multiprocessing.cpu_count(), train_sizes=np.linspace(.1, 1.0, 5))
            elif classifier is 'ADA':
                train_sizes, train_scores, test_scores = learning_curve(AdaBoostClassifier(
                    algorithm=tune['algorithm'], n_estimators=tune['n_estimators']), X, y, cv=cv, n_jobs=multiprocessing.cpu_count(), train_sizes=np.linspace(.1, 1.0, 5))
        except ValueError, err:
            self.log.error(
                "Cannot estimate learning curve for %s.\nReason:" % classifier)
            self.log.error(err)
            return

        train_scores_mean = np.mean(train_scores, axis=1)
        train_scores_std = np.std(train_scores, axis=1)
        test_scores_mean = np.mean(test_scores, axis=1)
        test_scores_std = np.std(test_scores, axis=1)

        model.setConvergence(self.isConverging(
            train_scores_mean, test_scores_mean))
        model.setPassLimit(np.max(train_scores_mean) >= 0.9)

        if display or filename:
            self.plot_learning_curve(_title[classifier], train_sizes, train_scores, test_scores,
                                     train_scores_mean, train_scores_std, test_scores_mean, test_scores_std, ylim=(0.7, 1.01))
            if filename:
                plt.savefig(self.generateFilename('LearningCurve'))
            if display:
                plt.show()
        return

    def isConverging(self, train_scores_mean, test_scores_mean):  # 1
        diff = train_scores_mean - test_scores_mean
        return all(a >= b for a, b in zip(diff[:-1], diff[1:]))

    def plot_learning_curve(self, title, train_sizes, train_scores, test_scores, train_scores_mean, train_scores_std, test_scores_mean, test_scores_std, ylim=None):
        plt.figure()
        plt.title(title)
        if ylim is not None:
            plt.ylim(*ylim)
        plt.xlabel("Data Set Size")
        plt.ylabel("Score")
        plt.grid()

        plt.fill_between(train_sizes, train_scores_mean - train_scores_std,
                         train_scores_mean + train_scores_std, alpha=0.1,
                         color="r")
        plt.fill_between(train_sizes, test_scores_mean - test_scores_std,
                         test_scores_mean + test_scores_std, alpha=0.1, color="g")
        plt.plot(train_sizes, train_scores_mean, 'o-', color="r",
                 label="Training score")
        plt.plot(train_sizes, test_scores_mean, 'o-', color="g",
                 label="Cross-validation score")

        plt.legend(loc="best")
        return plt

    def show_confusion_matrix(self, C, class_labels=['0', '1']):
        tn = C[0, 0]
        fp = C[0, 1]
        fn = C[1, 0]
        tp = C[1, 1]
        NP = fn+tp
        NN = tn+fp
        N = NP+NN

        fig = plt.figure(figsize=(8, 8))
        ax = fig.add_subplot(111)
        ax.imshow(C, interpolation='nearest', cmap=plt.cm.gray)

        # Draw the grid boxes
        ax.set_xlim(-0.5, 2.5)
        ax.set_ylim(2.5, -0.5)
        ax.plot([-0.5, 2.5], [0.5, 0.5], '-k', lw=2)
        ax.plot([-0.5, 2.5], [1.5, 1.5], '-k', lw=2)
        ax.plot([0.5, 0.5], [-0.5, 2.5], '-k', lw=2)
        ax.plot([1.5, 1.5], [-0.5, 2.5], '-k', lw=2)

        # Set xlabels
        ax.set_xlabel('Predicted Label', fontsize=16)
        ax.set_xticks([0, 1, 2])
        ax.set_xticklabels(class_labels + [''])
        ax.xaxis.set_label_position('top')
        ax.xaxis.tick_top()

        ax.xaxis.set_label_coords(0.34, 1.06)

        # Set ylabels
        ax.set_ylabel('True Label', fontsize=16, rotation=90)
        ax.set_yticklabels(class_labels + [''], rotation=90)
        ax.set_yticks([0, 1, 2])
        ax.yaxis.set_label_coords(-0.09, 0.65)

        # Fill primary metrics
        ax.text(0, 0,
                'True Neg: %d\n(Num Neg: %d)' % (tn, NN),
                va='center',
                ha='center',
                bbox=dict(fc='w', boxstyle='round,pad=1'))

        ax.text(0, 1,
                'False Neg: %d' % fn,
                va='center',
                ha='center',
                bbox=dict(fc='w', boxstyle='round,pad=1'))

        ax.text(1, 0,
                'False Pos: %d' % fp,
                va='center',
                ha='center',
                bbox=dict(fc='w', boxstyle='round,pad=1'))

        ax.text(1, 1,
                'True Pos: %d\n(Num Pos: %d)' % (tp, NP),
                va='center',
                ha='center',
                bbox=dict(fc='w', boxstyle='round,pad=1'))

        # Fill in secondary metrics: accuracy, true pos rate, etc...
        ax.text(2, 0,
                'False Pos Rate: %.2f' % (fp / (fp+tn+0.)),
                va='center',
                ha='center',
                bbox=dict(fc='w', boxstyle='round,pad=1'))

        ax.text(2, 1,
                'True Pos Rate: %.2f' % (tp / (tp+fn+0.)),
                va='center',
                ha='center',
                bbox=dict(fc='w', boxstyle='round,pad=1'))

        ax.text(2, 2,
                'Accuracy: %.2f \nSpecificity: %.2f \nPrecision: %.2f' % (
                    (tp+tn+0.)/N, (tn+0.)/NN, (tp+0.)/(tp+fp)),
                va='center',
                ha='center',
                bbox=dict(fc='w', boxstyle='round,pad=1'))

        ax.text(0, 2,
                'Neg Pre Val: %.2f' % (1-fn/(fn+tn+0.)),
                va='center',
                ha='center',
                bbox=dict(fc='w', boxstyle='round,pad=1'))

        ax.text(1, 2,
                'Prevalence: %.2f' % (NP/(NP+0.+NN)),
                va='center',
                ha='center',
                bbox=dict(fc='w', boxstyle='round,pad=1'))

        plt.tight_layout()
        if self.config.plot_to_file():
            plt.savefig(self.generateFilename('ConfusionMatrix'))
        if self.config.display_plots():
            plt.show()

    def Cross_Validation_Plot(self, X, Y, info, display=False, filename=None):  # 1
        # prepare configuration for cross validation test harness
        seed = 7

        # prepare models
        models = []
        models.append(('KNeighbor', KNeighborsClassifier()))
        models.append(('DTree', DecisionTreeClassifier()))
        models.append(('SVM', SVC()))
        models.append(('RForest', RandomForestClassifier()))
        models.append(('MLP', MLPClassifier()))
        models.append(('ADA', AdaBoostClassifier()))

        # evaluate each model in turn
        results = []
        res_class = {}
        names = []
        scoring = 'accuracy'
        err = 0
        counter = 0
        results_r2 = []
        results_squarred = []
        for name, model in models:
            try:
                kfold = model_selection.KFold(
                    n_splits=self.config.cv(), random_state=seed)
                cv_results = model_selection.cross_val_score(
                    model, X, Y, cv=kfold, scoring=scoring, n_jobs=multiprocessing.cpu_count())
                results.append(cv_results)
                names.append(name)
                res_class[name] = np.mean(cv_results)

            except ValueError:
                pass

        if self.config.display_plots() or self.config.plot_to_file():
            # boxplot algorithm comparison
            title = "Classifier Comparision "
            title1 = "\nData Set Size:" + str(info['overall_size']) + " , Malicious Apps:" + str(
                info['mal_size']) + " (" + "{:.2f}".format(info['mal_ratio']*100) + "%)"

            plt.title(title+title1)
            plt.boxplot(results)
            plt.ylabel("F1 score (%)")
            plt.grid(ls='dotted')
            plt.xticks([1, 2, 3, 4, 5, 6], names)

            if self.config.plot_to_file():
                plt.savefig(self.generateFilename('CrossVal'))
            if self.config.display_plots():
                plt.show()

        return res_class

    def ROC(self, X, y, model):
        n_samples, n_features = X.shape

        clsf = model.getClassifier()
        tune = model.getTune()

        random_state = np.random.RandomState(0)
        # concat on 2nd axis
        X = np.c_[X, random_state.randn(n_samples, 5 * n_features)]
        # Run classifier with cross-validation and plot ROC curves
        cv = StratifiedKFold(n_splits=self.config.cv())
        if clsf is 'KNeighbor':
            classifier = KNeighborsClassifier(
                n_neighbors=tune['n_neighbors'], weights=tune['weights'], algorithm=tune['algorithm'])
        elif clsf is 'SVM':
            classifier = SVC(kernel=tune['kernel'], C=tune['C'],
                             gamma=tune['gamma'], random_state=random_state, probability=True)
        elif clsf is 'DTree':
            classifier = DecisionTreeClassifier(min_weight_fraction_leaf=tune['min_weight_fraction_leaf'], class_weight=tune[
                                                'class_weight'], min_samples_split=tune['min_samples_split'], random_state=random_state)
        elif clsf is 'RForest':
            classifier = RandomForestClassifier(n_estimators=tune['n_estimators'], min_samples_split=tune['min_samples_split'],
                                                oob_score=tune['oob_score'], class_weight=tune['class_weight'], random_state=random_state)
        elif clsf is 'MLP':
            classifier = MLPClassifier(
                solver=tune['solver'], activation=tune['activation'], random_state=random_state)
        elif clsf is 'ADA':
            classifier = AdaBoostClassifier(
                algorithm=tune['algorithm'], n_estimators=tune['n_estimators'], random_state=random_state)

        mean_tpr = 0.0
        mean_fpr = np.linspace(0, 1, 100)

        colors = cycle(['cyan', 'indigo', 'seagreen',
                        'yellow', 'blue', 'darkorange'])
        lw = 2

        i = 0
        for (train, test), color in zip(cv.split(X, y), colors):
            probas_ = classifier.fit(X[train], y[train]).predict_proba(X[test])
            # Compute ROC curve and area the curve
            fpr, tpr, thresholds = roc_curve(y[test], probas_[:, 1])
            mean_tpr += interp(mean_fpr, fpr, tpr)
            mean_tpr[0] = 0.0
            roc_auc = auc(fpr, tpr)
            plt.plot(fpr, tpr, lw=lw, color=color,
                     label='ROC fold %d (area = %0.2f)' % (i, roc_auc))

            i += 1

        plt.plot([0, 1], [0, 1], linestyle='--', lw=lw, color='k')

        mean_tpr /= cv.get_n_splits(X, y)
        mean_tpr[-1] = 1.0
        mean_auc = auc(mean_fpr, mean_tpr)
        plt.plot(mean_fpr, mean_tpr, color='g', linestyle='--',
                 label='Mean ROC (area = %0.2f)' % mean_auc, lw=lw)

        plt.xlim([-0.05, 1.05])
        plt.ylim([-0.05, 1.05])
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title('Receiver operating characteristic: %s' % clsf)
        plt.legend(loc="lower right")
        if self.config.plot_to_file():
            plt.savefig(self.generateFilename('RoC'))
        if self.config.display_plots():
            plt.show()

    def formTuneDictionary(self):
        return dict(solver=None, learning_rate=None, activation=None, n_neighbors=None, weights=None, kernel=None, C=None, gamma=None,
                    min_weight_fraction_leaf=None, min_samples_split=None, oob_score=None, class_weight=None, algorithm='auto', n_estimators=2, max_depth=-1, batch_size=-1)

    def calulateParameterLimits(self):
        o_size = self.fv[self.maxi][self.maxj]['info']['overall_size']
        return int(o_size*self.config.test_size())

    def parameter_estimation(self, X, y, classifier):
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=self.config.test_size(), random_state=0)

        # Set the parameters for cross-validation
        _classifiers = {'KNeighbor': KNeighborsClassifier(),
                        'SVM': SVC(C=1),
                        'DTree': DecisionTreeClassifier(),
                        'RForest': RandomForestClassifier(),
                        'MLP': MLPClassifier(),
                        'ADA': AdaBoostClassifier()
                        }

        cont_par_limit = self.calulateParameterLimits()
        if cont_par_limit > 80:
            parameter_limit = 80
        else:
            parameter_limit = cont_par_limit

        # parameters to be traversed
        _tuned_parameters = {'SVM': [{'kernel': ['rbf'], 'gamma': [1e-3, 1e-4], 'C': [1, 10, 100, 1000]}, {'kernel': ['linear'], 'C': [1, 10, 100, 1000]}],
                             'KNeighbor': [{'n_neighbors': filter(lambda x: x % 2 != 0, list(range(4, parameter_limit))), 'weights': ['distance', 'uniform'], 'algorithm':['auto', 'ball_tree', 'kd_tree', 'brute']}],
                             'DTree': [{'max_depth': np.array(filter(lambda x: x % 5 == 0, list(range(4, parameter_limit)))), 'min_weight_fraction_leaf': [0., 0.2, 0.5], 'class_weight':['balanced', None], 'min_samples_split':list(np.linspace(0.1, 0.85, num=4))}],
                             'RForest': [{'n_estimators': filter(lambda x: x % 2 != 0, list(range(4, parameter_limit))), 'min_samples_split': list(np.linspace(0.1, 0.85, num=4)), 'oob_score': [True, False], 'class_weight':['balanced', None]}],
                             'MLP': [{'solver': ['lbfgs', 'sgd', 'adam'], 'activation':['identity', 'logistic', 'tanh', 'relu'], 'batch_size':[200]},
                                     {'solver': ['sgd'], 'activation':['identity', 'logistic', 'tanh', 'relu'], 'learning_rate':['constant', 'invscaling', 'adaptive'], 'batch_size':[200]}],
                             'ADA': [{'n_estimators': filter(lambda x: x % 2 != 0, list(range(20, parameter_limit))), 'algorithm': ['SAMME', 'SAMME.R']}]
                             }

        scores = ['accuracy']
        _results = {}
        if classifier is None:
            print 'Estimation of most accurate classifiers and tuning parameters.....'
            for class_name, classifier in _classifiers.iteritems():
                concat = []
                for score in scores:
                    partial = []
                    print("# %s: Tuning hyper-parameters for %s" %
                          (class_name, score))
                    try:
                        clf = GridSearchCV(classifier, _tuned_parameters[class_name], cv=self.config.cv(
                        ), scoring='%s' % score, n_jobs=multiprocessing.cpu_count())
                        clf.fit(X_train, y_train)
                    except ValueError, err:
                        print 'Exception'
                        print err
                        self.log.error(
                            "Cannot estimate parameters for %s.\nReason:" % classifier)
                        self.log.error(err)
                        break

                    y_true, y_pred = y_test, clf.predict(X_test)
                    qq = classification_report(y_true, y_pred).split()
                    partial.append({'score': score})
                    indi_scores = {qq[0]: float(qq[17]), qq[1]: float(
                        qq[18]), qq[2]: float(qq[19])}
                    partial.append({'individual': indi_scores})
                    partial.append(
                        {score: round(np.max(clf.cv_results_['mean_test_score']), 4)})
                    partial.append({'tune': clf.best_params_})
                    _results[class_name] = partial
            print 'Estimation of most accurate classifiers and tuning parameters.....[OK]'

        else:
            for score in scores:
                partial = []
                print (
                    " Tunning parameters for alternative classifier.......%s" % classifier)
                try:
                    clf = GridSearchCV(_classifiers[classifier], _tuned_parameters[classifier], cv=self.config.cv(
                    ), scoring='%s' % score, n_jobs=multiprocessing.cpu_count())
                    clf.fit(X_train, y_train)
                except ValueError, err:
                    self.log.error(
                        "Cannot estimate parameters for %s.\nReason:" % classifier)
                    self.log.error(err)
                    break
                y_true, y_pred = y_test, clf.predict(X_test)
                qq = classification_report(y_true, y_pred).split()
                partial.append({'score': score})
                indi_scores = {qq[0]: float(qq[17]), qq[1]: float(
                    qq[18]), qq[2]: float(qq[19])}
                partial.append({'individual': indi_scores})
                partial.append(
                    {score: round(np.max(clf.cv_results_['mean_test_score']), 4)})
                partial.append({'tune': clf.best_params_})
                _results[classifier] = partial

        return _results

    def getBestClassifier(self, results):
        max = 0.0
        best_classifier = ''
        best_tune = ''

        for classifier, res in results.iteritems():
            if max < res[2]['accuracy']:
                max = res[2]['accuracy']
                best_classifier = classifier
                best_tune = res[3]['tune']

        return best_classifier, best_tune, max

    def getMaxDataSetSize(self, fv):
        max, max_i, max_j, i = -1, -1, -1, -1
        for i in range(0, len(fv)):
            for j in range(0, len(fv[i])):
                if fv[i][j]['vector'].shape[0] > max:
                    max = fv[i][j]['vector'].shape[0]
                    max_i = i
                    max_j = j
        return max_i, max_j
