import pandas as pd
import tensorflow as tf
from keras.models import Sequential
from keras.layers import Dense
from keras.wrappers.scikit_learn import KerasClassifier
from keras.utils import np_utils
from sklearn.model_selection import cross_val_score
from sklearn.model_selection import KFold
from sklearn.preprocessing import LabelEncoder
from sklearn.pipeline import Pipeline
from sklearn.utils import shuffle
import sys
from sklearn.model_selection import train_test_split
from matplotlib import pyplot as plt
import seaborn as sns
import numpy as np
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix, precision_score, recall_score, f1_score
from sklearn import svm
import xgboost
import seaborn as sns
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.discriminant_analysis import QuadraticDiscriminantAnalysis as QDA
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis as LDA
from sklearn.ensemble import AdaBoostClassifier 
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
import time

def initGPU():
    gpus = tf.config.experimental.list_physical_devices('GPU')
    if gpus:
        try:
            # Currently, memory growth needs to be the same across GPUs
            for gpu in gpus:
                tf.config.experimental.set_memory_growth(gpu, True)
            logical_gpus = tf.config.experimental.list_logical_devices('GPU')
            print(len(gpus), "Physical GPUs,", len(logical_gpus), "Logical GPUs")
        except RuntimeError as e:
            # Memory growth must be set before GPUs have been initialized
            print(e)

def LoadSubset(filename, lblNum=4, header=0):
	print("Loading dataset: ",filename)
	# load dataset
	data = filename
	
	dataframe = pd.read_csv(data, header=header)
	
	#if the data is a timeseries, it should not be suffled!
	#df = shuffle(dataframe)
	df = dataframe
	dataset = df.values
	X = dataset[:,0:lblNum].astype(float)
	if header != None:#training data
		Y,levels = pd.factorize(df['label'])
	else:
		Y = dataset[:,lblNum].astype(str)
		Y = dataset[:,lblNum]
		levels = None
	return X, Y, levels

def testingFile():
	import glob
	files = glob.glob("withHeader/*")
	#print(files)
	#print(len(files))
	return files

def ClassicML2(X_train, X_test, Y_train, Y_test, levels =None, test=False, fparam= ""):
	timeDB = {}
	precisionDB = {}
	#name = ["xgboost","KNN","GaussianNB","QDA","LDA","Adaboost","Gradienboost","Randomforest","Decisiontree","LogisticRegress"]#,"SVM RBF"]
	name = ["xgboost","KNN","GaussianNB","Randomforest","Decisiontree"]
	name = ["Decisiontree"]#debug only
	classifiers = []
	#classifiers.append(xgboost.XGBClassifier())
	#classifiers.append(KNeighborsClassifier())
	#classifiers.append(GaussianNB())
	#classifiers.append(RandomForestClassifier() )
	classifiers.append(DecisionTreeClassifier() )
	
	ctr=0
	for clf in classifiers:
		print(">> Classifier:",name[ctr])
		t0 = time.time()
		clf.fit(X_train, Y_train)
		t1 = time.time()
		y_pred= clf.predict(X_test)
		t2 = time.time()
		timeDB[name[ctr]] = [t1-t0, t2-t1]
		print(classification_report(Y_test,y_pred,target_names=levels))
		
		sns.reset_orig()
		sns.set()
		
		cf_matrix = pd.crosstab(levels[Y_test],levels[y_pred])
		cf_matrix = cf_matrix.astype('float') / cf_matrix.sum(axis=1)[:, np.newaxis]
		fig, ax = plt.subplots(figsize=(10,10))
		sns.heatmap(cf_matrix, linewidths=1, annot=True, ax=ax, cmap="Blues", fmt='.0%')
		
		
		plt.savefig("perLabel/"+name[ctr]+fparam+'.png')
		plt.close()
		
		if test and name[ctr]=="Decisiontree":
			#flist = testingFile()
			flist = ["perLabel/All_Unique_Flow.txt"]
			#for i in range(10):
			for fname in flist:
				print(fname)
				name = fname.split("/")[1]
				#print("testing on:",fname, name)
				name = name.split(".")[0]
				#fname = "Flow_0"+str(i)+".txt"
				
				XT, YT, levels = LoadSubset(fname)
				X_testT, Y_testT = XT, YT
				predictions = clf.predict(X_testT)
				print(classification_report(Y_testT,predictions,target_names=levels))
				
				#	#accT = accuracy_score(Y_testT, predictions)
				#	#print(accT)
				#precT = precision_score(Y_testT, predictions, average='micro')
				#print("Precison",precT)
				#precisionDB[name]  = str(precT)
				#	#rclT = recall_score(Y_testT, predictions, average='micro')
				#	#f1sT = f1_score(Y_testT, predictions, average='micro')
				#	#print(accT, precT, rclT, f1sT)
				#	#accT = accuracy_score(Y_testT, predictions)
				#	#precT = precision_score(Y_testT, predictions, average='weighted')
				#	#rclT = recall_score(Y_testT, predictions, average='weighted')
				#	#f1sT = f1_score(Y_testT, predictions, average='weighted')
				#	#print(accT, precT, rclT, f1sT)
				#	#exit()
					#
				#	#sns.reset_orig()
				#	#sns.set()
				#	#
				
				cf_matrix = pd.crosstab(levels[Y_testT],levels[predictions])
				cf_matrix = cf_matrix.astype('float') / cf_matrix.sum(axis=1)[:, np.newaxis]
				fig, ax = plt.subplots(figsize=(10,10))
				sns.heatmap(cf_matrix, linewidths=1, annot=True, ax=ax, cmap="Blues", fmt='.0%')
				
				plt.savefig("perLabel/"+name+fparam+'.png')
				#plt.savefig(name[ctr]+"_"+str(i)+'.png')
				plt.close()
				
				#	cmT = confusion_matrix(Y_testT, predictions)
				#	cmT = cmT.astype('float') / cmT.sum(axis=1)[:, np.newaxis]	
				#	sns.heatmap(cmT, annot=True, cmap="Blues", fmt='.0%')
				#	plt.savefig("withHeader/"+name+'.png')
				#	plt.close()
		ctr+=1	
	with open("precision.stat","w") as fo:
		for k in precisionDB:
			fo.write(k+","+precisionDB[k]+"\n")
	#timing debug only
	#for k in timeDB:
	#	print(k, timeDB[k])
		
if len(sys.argv) < 2:
	print("Format: py ML.py <size>")
	print("size in ten-thousand (K)")
	print("e.g 10 --> 10000")
	exit()
dsSize = sys.argv[1]
training_file = "perLabel/dataset_"+dsSize+"K.txt"
fparam = dsSize+ "K"

#X, Y, levels = LoadSubset("dataset_minimal.csv")
#X, Y, levels = LoadSubset("dataset_normal.csv")
#X, Y, levels = LoadSubset("perLabel/dataset_10K.txt")
#X, Y, levels = LoadSubset("perLabel/dataset_30K.txt")

X, Y, levels = LoadSubset(training_file)

X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.1, random_state=13)
ClassicML2(X_train, X_test, Y_train, Y_test, levels, True, fparam)

#recap:
timing_xgboost 	 	= [   6.827908754348755, 0.035971879959106445]
timing_KNN 		 	= [ 0.07700061798095703,   0.5129950046539307]
timing_GaussianNB 	= [0.011996746063232422, 0.006010770797729492]
timing_Randomforest = [   4.050998687744141,   0.2800283432006836]
timing_Decisiontree = [ 0.07500481605529785,0.0030057430267333984]
timing2_xgboost 	= [  12.483039379119873,  0.04895973205566406]
timing2_KNN 		= [ 0.09301137924194336,   0.6159625053405762]
timing2_GaussianNB 	= [0.015992403030395508, 0.007009744644165039]
timing2_Randomforest= [   5.149027347564697,  0.37400054931640625]
timing2_Decisiontree= [ 0.10900521278381348, 0.003993034362792969]

exit()
