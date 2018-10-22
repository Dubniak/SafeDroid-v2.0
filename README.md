# Welcome to SafeDroid v2.0 #
A Framework for detecting malicious Android applications

## Introduction ##
[SafeDroid v2.0](https://sites.google.com/di.uniroma1.it/safedroid2/home) is a terminal-based framework for reverse engineering, 
static analysis and classification of Android applications. An early version of the framework can be found [here]( https://github.com/Dubniak/SafeDroid). 

SafeDroid comes under the GNU GENERAL PUBLIC LICENSE.

The main goal of our work, besides the automated production of fully sufficient prediction and classification 
models, is to offer an out-of-the-box framework that 
can be employed by the Android security researchers to efficiently experiment to find effective solutions: the 
framework makes it possible to test different combinations of machine learning classifiers, with a high degree of freedom and flexibility in the choice of features to consider, 
such as dataset balance and dataset selection. For more detailed information, please read the [published research paper](https://www.hindawi.com/journals/scn/2018/4672072/)

## Installation ##
SD runs on Python 2.7. 
Python 2.7 or newer is standard in all Linux systems. 

1.	Install the dependencies. SafeDroid v2.0 depends on the following packages:
-	Pandas 
-	Sklearn 0.19.2
-	SciPy 1.1.0
-	joblib 0.12.5 
-	matplotlib 

Installation :

`pip install -r requirements.txt`

It also needs:
-	python-tk 
-	mysqlclient 1.3.13 (sudo install mysqlcient) 

Install them as:

`sudo apt install python-tk mysqlclient`

## Configure database ##
To run the framework, execute 
python safedroid.py [-l] [-m] [-b] [-t] [-r] [-R]

The available parameters are 
`	-h, --help            show this help message and exit

	-l LOG, --log=LOG     Log level {DEBUG, INFO, WARN, ERROR, CRITICAL}
	
	-t TESTING_MODE, --testing-mode=TESTING_MODE
							Testing mode {FOLDERS, SET, SINGLE}
  
	-m MALICIOUS_FOLDER, --malicious-folder=MALICIOUS_FOLDER
							Malicious input folder {ABSOLUTE PATH}
  
	-b BENIGN_FOLDER, --benign-folder=BENIGN_FOLDER
							Benign input folder {ABSOLUTE PATH}
							
	-r RESET, --reset=RESET
							Reset database schema
  
	-R RESET, --Reset=RESET
							Reset database schema and exit
`
