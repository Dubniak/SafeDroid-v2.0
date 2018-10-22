"""
Part of the SafeDroid v2.0 FrameWork.
Author : Arygriou Marios
Year : 2017
The framework is distributed under the GNU General Public License v3.0
"""
import os
from time import gmtime, strftime


class Report:
    def __init__(self, exec_time, anal_time, fv_time, tune_time, train_time, ben_folder, mal_folder, size):
        self.createDir()
        self.fname = strftime("%Y-%m-%d_%H:%M:%S", gmtime())
        self.data_pool = os.path.join(os.getcwd(), 'data_pool/')
        self.directory = os.path.join(os.getcwd(), 'Report/')
        self.accuracy = -0.1
        self.exec_time = exec_time
        self.anal_time = anal_time
        self.fv_time = fv_time
        self.tune_time = tune_time
        self.train_time = train_time
        self.source_ben = ben_folder
        self.source_mal = mal_folder
        self.size = size / 1000

    def setAccuracy(self, accuracy):
        self.accuracy = accuracy

    def setClassifier(self, cls):
        self.classifier = cls

    def setFVsize(self, fvs):
        self.fvsize = fvs

    def createDir(self):
        if not os.path.exists('Report'):
            os.mkdir('Report')

    def setF1(self, f1):
        self.f1macro = f1['macro']
        self.f1weighted = f1['weighted']
        self.f1micro = f1['micro']

    def setConfusion(self, C):
        self.tn = C[0, 0]
        self.fp = C[0, 1]
        self.fn = C[1, 0]
        self.tp = C[1, 1]
        NP = self.fn+self.tp
        NN = self.tn+self.fp
        N = NP+NN

        self.fpr = self.fp / (self.fp+self.tn+0.)
        self.tpr = self.tp / (self.tp+self.fn+0.)
        self.spcf = (self.tn+0.)/NN
        self.prc = (self.tp+0.)/(self.tp+self.fp)
        self.npv = 1-self.fn/(self.fn+self.tn+0.)
        self.prv = NP/(NP+0.+NN)

    def getFeatureVectorSize(self):
        size = 0
        csv_files = ['applications.csv', 'api.csv', 'apptoapi.csv']
        for f in csv_files:
            size += os.stat(os.path.join(self.data_pool, f)).st_size
        return float("{0:.1f}".format(float(size)/1000))

    def AnalysisThroughput(self):
        try:
            return float("{0:.2f}".format(self.size/float(self.anal_time)))
        except ZeroDivisionError:
            return 0.0

    def TrainThroughput(self):
        size = self.getFeatureVectorSize()
        try:
            return float("{0:.1f}".format(float(size)/float(self.train_time)))
        except ZeroDivisionError:
            return 0.0

    def saveReport(self):
        target = open(os.path.join(self.directory, self.fname), 'w')
        target.write("SafeDroid v2.0 - Report\nProduced at %s\n" % self.fname)
        target.write("For incidents during execution refer to safedroid.log\n")
        target.write("\nReport Start\n\n")
        target.write("Raw Data Size : %.2f KB \n" % float(self.size))
        target.write("Overall Execution Time : %s sec\n" % self.exec_time)
        target.write("Analysis Time : %s sec\n" % self.anal_time)
        target.write("Feature Vector Time: %s sec\n" % self.fv_time)
        target.write("Tuning Time: %s sec\n" % self.tune_time)
        target.write("Training Time: %s sec\n" % self.train_time)
        target.write("Analysis Throughput Time: %.2f KB per sec \n" %
                     self.AnalysisThroughput())
        target.write("Training Throughput Time: %.2f KB per sec \n\n" %
                     self.TrainThroughput())
        target.write(50*"#")
        target.write("\n\n")
        target.write("Information about prediction model\n")
        target.write("Classifier: %s\n" % self.classifier)
        target.write("Accuracy: %f\n" % self.accuracy)
        target.write("Number of features considered: %d\n\n" % self.fvsize)
        target.write("F1 metrics \n")
        target.write("macro : %f\nweighted : %f\nmicro : %f \n\n" %
                     (self.f1macro, self.f1weighted, self.f1micro))
        target.write("Confusion Matrix\n")
        target.write("\tTP : %.3f | TN : %.3f\n\tFP : %.3f | FN : %.3f\n" % (
            self.tp, self.tn, self.fp, self.fn))
        target.write("\nSpecificity: %.2f\n" % self.spcf)
        target.write("Precision: %.2f\n" % self.prc)
        target.write("Prevalence: %.2f\n" % self.prv)
        target.write("Negative Prediction Value: %.2f\n" % self.npv)
        target.write("True Positive Rate: %.2f\n" % self.tpr)
        target.write("False Positive Rate: %.2f\n" % self.fpr)
        target.write("\nEnd of Report\n\n")
        target.close()
