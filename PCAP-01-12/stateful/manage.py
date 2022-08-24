import sys,binascii
from scapy.all import *

tsdata = {}
tsdata["NTP"] = [1543660500.0, 1543661100.0]
tsdata["DNS"] = [1543661520.0, 1543662300.0]
tsdata["LDAP"] = [1543663320.0, 1543663920.0]
				 
tsdata["MSSQL"] = [1543664160.0, 1543664700.0]
tsdata["NetBIOS"] = [1543665000.0, 1543665600.0]
tsdata["SNMP"] = [1543666320.0, 1543666980.0]
tsdata["SSDP"] = [1543667220.0, 1543667820.0]
tsdata["UDP"] = [1543668300.0, 1543669740.0]
tsdata["UDP-Lag"] = [1543669860.0, 1543670100.0]
tsdata["WebDDoS"] = [1543670280.0, 1543670940.0]
tsdata["SYN"] = [1543670940.0, 1543671240.0]
tsdata["TFTP"] = [1543671300.0, 1543684500.0]

DSIndex = {}#raw estimation for dataset selection
DSIndex["Benign"] = [[188, 191],[196, 381],[440,443],[467,474],[485,486],[569,571]]
DSIndex["NTP"] = [1, 187]
DSIndex["DNS"] = [192, 195] 		
DSIndex["LDAP"] = [382, 439] 	
DSIndex["MSSQL"] = [444, 466] 	
DSIndex["NetBIOS"] = [475, 484] 	
DSIndex["SNMP"] = [487, 568] 	
DSIndex["SSDP"] = [572, 592] 	
DSIndex["UDP"] = [593, 616] 		
DSIndex["UDP-Lag"] = [617] 	
DSIndex["WebDDoS"] = [617] 	
DSIndex["SYN"] = [618, 619] 		
DSIndex["TFTP"] = [621, 817] 	

def getLabel(start, end):
	for k in tsdata:
		if (start > tsdata[k][0] and start < tsdata[k][1]) or ( end > tsdata[k][0] and end < tsdata[k][1]):
			return k
	return "Benign"

def relabel(i):
	fname = "Flow_0"+str(i)+".csv"
	print(fname)
	foutput = "Flow_0"+str(i)+".txt"
	labelData = []
	with open(fname, "r") as fr:
		line = fr.readline()
		data = line.split(",")
		while len(data) > 1:
			#							  pkt_ID,  IP_Protocol, 			  time, 	   dt, pktcounter, bytesize, 	 label, tcp_State 
			#192_168_50_1:45306-172_16_0_5:634#0,  			17,  1543661863.395236,  0.248415,  	  193,  	448,	Benign, 		0
			ts = float(data[2])
			dt = float(data[3])
			lbl = getLabel(ts, ts+dt)
			labelData.append( [data[1], data[3], data[4], data[5], lbl ] )
			#print(i, ts, datetime.utcfromtimestamp(int(ts)), lbl)
			
			line = fr.readline()
			data = line.split(",")
	with open(foutput, "w") as fo:
		for k in labelData:
			fo.writelines(",".join(k)+"\n")
	
def countUnique():
	DB = {}
	All = {}
	labelstr = ["Benign","NTP","DNS","LDAP","MSSQL","NetBIOS","SNMP","SSDP","UDP","SYN","TFTP"]
	for lbl in labelstr:
		DB[lbl] = set()
		All[lbl] = 0
	
	#res = {}
	for i in range(819):
		fname = "Flow_0"+str(i)+".txt"
		print(fname)
		with open(fname, "r") as fr:
			line = fr.readline()
			data = line.split(",")
			while len(data) > 3:
				dt = line[:-1]
				#print(dt, len(data))
			
				lbl = data[4][:-1]
				if lbl in labelstr:
					DB[lbl].add( dt )
					All[lbl] += 1
					
				line = fr.readline()
				data = line.split(",")
	#recap
	totU = 0
	totA = 0
	for k in DB:
		#res[k] = len(DB[k])
		totU += len(DB[k])
		totA += All[k]
		print(k, len(DB[k]), All[k])
	print(totU, totA)
	#return res
		#print(DB[k])



def calcStat():
	data = {}
	data["Benign"] 	= [ 143917, 7119800 ] #  2.0213 %
	data["NTP"] 	= [ 544217, 1192326 ] # 45.6433 %
	data["DNS"] 	= [  14361,   15275 ] # 94.0163 %
	data["LDAP"]	= [  48274, 2069804 ] #  2.3322 %
	data["MSSQL"] 	= [  15015, 3512398 ] #  0.4274 %
	data["NetBIOS"] = [   6327, 3936234 ] #  0.1607 %
	data["SNMP"] 	= [  31172, 4812873 ] #  0.6476 %
	data["SSDP"]	= [ 141443, 2583460 ] #  5.4749 %
	data["UDP"] 	= [ 138198, 3111189 ] #  4.4419 %
	data["SYN"] 	= [ 209265, 1716572 ] # 12.1908 %
	data["WebDDoS"] = [   1019,    1234 ] # 82.5769 %
	data["UDP-Lag"] = [   4103,    4387 ] # 93.5263 %
	data["TFTP"] 	= [ 674148,19941977 ] #  3.3805 %
	
	totU = 0
	totA = 0
	for k in data:
		totU += data[k][0]
		totA += data[k][1]
		print(data[k][0]/data[k][1] * 100 , "%")
	print("Total unique Flows:", totU)
	print("Total all Flows:   ", totA)
	#Total unique Flows:  1971459
	#Total all Flows:    50017529
	#unique flows = 0.0394 %
	
def genFileset():
	data = {}
	data["Benign"] 	= [ 143917, 7119800 ] #  2.0213 %
	data["LDAP"]	= [  48274, 2069804 ] #  2.3322 %
	data["MSSQL"] 	= [  15015, 3512398 ] #  0.4274 %
	data["NetBIOS"] = [   6327, 3936234 ] #  0.1607 %
	data["SNMP"] 	= [  31172, 4812873 ] #  0.6476 %
	data["SSDP"]	= [ 141443, 2583460 ] #  5.4749 %
	data["UDP"] 	= [ 138198, 3111189 ] #  4.4419 %
	data["SYN"] 	= [ 209265, 1716572 ] # 12.1908 %
	data["TFTP"] 	= [ 674148,19941977 ] #  3.3805 %
	DSIndex = {}
	DSIndex["Benign"] = [[188, 191],[196, 381],[440,443],[467,474],[485,486],[569,571]]
	DSIndex["NTP"] = [1, 187]
	DSIndex["DNS"] = [192, 195] 
	DSIndex["LDAP"] = [382, 439] 	
	DSIndex["MSSQL"] = [444, 466] 	
	DSIndex["NetBIOS"] = [475, 484] 	
	DSIndex["SNMP"] = [487, 568] 	
	DSIndex["SSDP"] = [572, 592] 	
	DSIndex["UDP"] = [593, 616] 		
	DSIndex["SYN"] = [618, 619] 		
	DSIndex["TFTP"] = [621, 817] 	
	fileset = {}
	count = 10000
	for lbl in DSIndex:
		fileset[lbl] = []
		if lbl == "Benign":
			for i in DSIndex[lbl]:
				a, b =i[0],i[1]
				fileset[lbl].extend(list(range(a,b+1)))
		else:
			a, b = DSIndex[lbl][0], DSIndex[lbl][1]
			if lbl == "NTP" or lbl == "DNS":
				print(lbl,list(range(a,b+1)))
			fileset[lbl].extend(list(range(a,b+1)))
		print(lbl, len(fileset[lbl]), count/len(fileset[lbl]))
def genMinimal():
	foutput = "dataset_minimal.csv"
	with open(foutput, "w") as fo:
		fo.writelines("Proto,delta,counter,bytes,label\n")
	dataset = {}
	fs = {}
	#fs["Benign"] = [188, 189]#debug only
	fs["Benign"] = [188, 189, 190, 191, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261, 262, 263, 264, 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276, 277, 278, 279, 280, 281, 282, 283, 284, 285, 286, 287, 288, 289, 290, 291, 292, 293, 294, 295, 296, 297, 298, 299, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 311, 312, 313, 314, 315, 316, 317, 318, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 332, 333, 334, 335, 336, 337, 338, 339, 340, 341, 342, 343, 344, 345, 346, 347, 348, 349, 350, 351, 352, 353, 354, 355, 356, 357, 358, 359, 360, 361, 362, 363, 364, 365, 366, 367, 368, 369, 370, 371, 372, 373, 374, 375, 376, 377, 378, 379, 380, 381, 440, 441, 442, 443, 467, 468, 469, 470, 471, 472, 473, 474, 485, 486, 569, 570, 571]
	fs["LDAP"] = [382, 383, 384, 385, 386, 387, 388, 389, 390, 391, 392, 393, 394, 395, 396, 397, 398, 399, 400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413, 414, 415, 416, 417, 418, 419, 420, 421, 422, 423, 424, 425, 426, 427, 428, 429, 430, 431, 432, 433, 434, 435, 436, 437, 438, 439]
	fs["MSSQL"] = [444, 445, 446, 447, 448, 449, 450, 451, 452, 453, 454, 455, 456, 457, 458, 459, 460, 461, 462, 463, 464, 465, 466]
	fs["NetBIOS"] = [475, 476, 477, 478, 479, 480, 481, 482, 483, 484]
	fs["SNMP"] = [487, 488, 489, 490, 491, 492, 493, 494, 495, 496, 497, 498, 499, 500, 501, 502, 503, 504, 505, 506, 507, 508, 509, 510, 511, 512, 513, 514, 515, 516, 517, 518, 519, 520, 521, 522, 523, 524, 525, 526, 527, 528, 529, 530, 531, 532, 533, 534, 535, 536, 537, 538, 539, 540, 541, 542, 543, 544, 545, 546, 547, 548, 549, 550, 551, 552, 553, 554, 555, 556, 557, 558, 559, 560, 561, 562, 563, 564, 565, 566, 567, 568]
	fs["SSDP"] = [572, 573, 574, 575, 576, 577, 578, 579, 580, 581, 582, 583, 584, 585, 586, 587, 588, 589, 590, 591, 592]
	fs["UDP"] = [593, 594, 595, 596, 597, 598, 599, 600, 601, 602, 603, 604, 605, 606, 607, 608, 609, 610, 611, 612, 613, 614, 615, 616]
	fs["SYN"] = [618, 619]
	fs["TFTP"] = [621, 622, 623, 624, 625, 626, 627, 628, 629, 630, 631, 632, 633, 634, 635, 636, 637, 638, 639, 640, 641, 642, 643, 644, 645, 646, 647, 648, 649, 650, 651, 652, 653, 654, 655, 656, 657, 658, 659, 660, 661, 662, 663, 664, 665, 666, 667, 668, 669, 670, 671, 672, 673, 674, 675, 676, 677, 678, 679, 680, 681, 682, 683, 684, 685, 686, 687, 688, 689, 690, 691, 692, 693, 694, 695, 696, 697, 698, 699, 700, 701, 702, 703, 704, 705, 706, 707, 708, 709, 710, 711, 712, 713, 714, 715, 716, 717, 718, 719, 720, 721, 722, 723, 724, 725, 726, 727, 728, 729, 730, 731, 732, 733, 734, 735, 736, 737, 738, 739, 740, 741, 742, 743, 744, 745, 746, 747, 748, 749, 750, 751, 752, 753, 754, 755, 756, 757, 758, 759, 760, 761, 762, 763, 764, 765, 766, 767, 768, 769, 770, 771, 772, 773, 774, 775, 776, 777, 778, 779, 780, 781, 782, 783, 784, 785, 786, 787, 788, 789, 790, 791, 792, 793, 794, 795, 796, 797, 798, 799, 800, 801, 802, 803, 804, 805, 806, 807, 808, 809, 810, 811, 812, 813, 814, 815, 816, 817]	
	#fs["TFTP"] = [621, 622]#debug only
	num = {}
	num["Benign"] = 49	
	num["LDAP"] = 173
	num["MSSQL"] = 435
	num["NetBIOS"] = 1000
	num["SNMP"] = 122
	num["SSDP"] = 477
	num["UDP"] = 417
	num["SYN"] = 5000
	num["TFTP"] = 51
	for lbl in fs:
		dataset[lbl] = []
		for index in fs[lbl]:
			fname = "Flow_0"+str(index)+".txt"
			print(fname)
			#read file & save num-size dataset
			ctr = 0
			complete = False
			with open(fname, "r") as fr:
				line = fr.readline()
				data = line.split(",")
				while len(data) > 3 and (not complete):	
					#cek is the label is same
					curlbl = data[4][:-1]
					if curlbl == lbl:
						
						#save to the dataset
						#dt = float(data[1]) * 10**6
						#buf = data[0] +","+ str(int(dt)) +","+ data[2] +","+ data[3] +","+ curlbl
						#dataset[lbl].append(buf)
						dataset[lbl].append(line)
						ctr +=1
						if ctr >= num[lbl]:
							complete = True
					line = fr.readline()
					data = line.split(",")
		#for k in  dataset[lbl]:
		#	print(k)
		with open(foutput, "a") as fo:
			for k in dataset[lbl]:
				#fo.writelines(k+"\n")
				fo.writelines(k)
		
def genNormal():
	foutput = "dataset_normal.csv"
	with open(foutput, "w") as fo:
		fo.writelines("Proto,delta,counter,bytes,label\n")
	dataset = {}
	data = {}
	data["Benign"] 	= [ 143917, 7119800 ] #  2.0213 %
	data["NTP"] 	= [ 544217, 1192326 ] # 45.6433 %
	data["DNS"] 	= [  14361,   15275 ] # 94.0163 %
	data["LDAP"]	= [  48274, 2069804 ] #  2.3322 %
	data["MSSQL"] 	= [  15015, 3512398 ] #  0.4274 %
	data["NetBIOS"] = [   6327, 3936234 ] #  0.1607 %
	data["SNMP"] 	= [  31172, 4812873 ] #  0.6476 %
	data["SSDP"]	= [ 141443, 2583460 ] #  5.4749 %
	data["UDP"] 	= [ 138198, 3111189 ] #  4.4419 %
	data["SYN"] 	= [ 209265, 1716572 ] # 12.1908 %
	data["TFTP"] 	= [ 674148,19941977 ] #  3.3805 %
	fs = {}
	fs["Benign"] = [188, 189, 190, 191, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261, 262, 263, 264, 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276, 277, 278, 279, 280, 281, 282, 283, 284, 285, 286, 287, 288, 289, 290, 291, 292, 293, 294, 295, 296, 297, 298, 299, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 311, 312, 313, 314, 315, 316, 317, 318, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 332, 333, 334, 335, 336, 337, 338, 339, 340, 341, 342, 343, 344, 345, 346, 347, 348, 349, 350, 351, 352, 353, 354, 355, 356, 357, 358, 359, 360, 361, 362, 363, 364, 365, 366, 367, 368, 369, 370, 371, 372, 373, 374, 375, 376, 377, 378, 379, 380, 381, 440, 441, 442, 443, 467, 468, 469, 470, 471, 472, 473, 474, 485, 486, 569, 570, 571]
	fs["NTP"] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187]
	fs["DNS"] = [192, 193, 194, 195]
	fs["LDAP"] = [382, 383, 384, 385, 386, 387, 388, 389, 390, 391, 392, 393, 394, 395, 396, 397, 398, 399, 400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413, 414, 415, 416, 417, 418, 419, 420, 421, 422, 423, 424, 425, 426, 427, 428, 429, 430, 431, 432, 433, 434, 435, 436, 437, 438, 439]
	fs["MSSQL"] = [444, 445, 446, 447, 448, 449, 450, 451, 452, 453, 454, 455, 456, 457, 458, 459, 460, 461, 462, 463, 464, 465, 466]
	fs["NetBIOS"] = [475, 476, 477, 478, 479, 480, 481, 482, 483, 484]
	fs["SNMP"] = [487, 488, 489, 490, 491, 492, 493, 494, 495, 496, 497, 498, 499, 500, 501, 502, 503, 504, 505, 506, 507, 508, 509, 510, 511, 512, 513, 514, 515, 516, 517, 518, 519, 520, 521, 522, 523, 524, 525, 526, 527, 528, 529, 530, 531, 532, 533, 534, 535, 536, 537, 538, 539, 540, 541, 542, 543, 544, 545, 546, 547, 548, 549, 550, 551, 552, 553, 554, 555, 556, 557, 558, 559, 560, 561, 562, 563, 564, 565, 566, 567, 568]
	fs["SSDP"] = [572, 573, 574, 575, 576, 577, 578, 579, 580, 581, 582, 583, 584, 585, 586, 587, 588, 589, 590, 591, 592]
	fs["UDP"] = [593, 594, 595, 596, 597, 598, 599, 600, 601, 602, 603, 604, 605, 606, 607, 608, 609, 610, 611, 612, 613, 614, 615, 616]
	fs["SYN"] = [618, 619]
	fs["TFTP"] = [621, 622, 623, 624, 625, 626, 627, 628, 629, 630, 631, 632, 633, 634, 635, 636, 637, 638, 639, 640, 641, 642, 643, 644, 645, 646, 647, 648, 649, 650, 651, 652, 653, 654, 655, 656, 657, 658, 659, 660, 661, 662, 663, 664, 665, 666, 667, 668, 669, 670, 671, 672, 673, 674, 675, 676, 677, 678, 679, 680, 681, 682, 683, 684, 685, 686, 687, 688, 689, 690, 691, 692, 693, 694, 695, 696, 697, 698, 699, 700, 701, 702, 703, 704, 705, 706, 707, 708, 709, 710, 711, 712, 713, 714, 715, 716, 717, 718, 719, 720, 721, 722, 723, 724, 725, 726, 727, 728, 729, 730, 731, 732, 733, 734, 735, 736, 737, 738, 739, 740, 741, 742, 743, 744, 745, 746, 747, 748, 749, 750, 751, 752, 753, 754, 755, 756, 757, 758, 759, 760, 761, 762, 763, 764, 765, 766, 767, 768, 769, 770, 771, 772, 773, 774, 775, 776, 777, 778, 779, 780, 781, 782, 783, 784, 785, 786, 787, 788, 789, 790, 791, 792, 793, 794, 795, 796, 797, 798, 799, 800, 801, 802, 803, 804, 805, 806, 807, 808, 809, 810, 811, 812, 813, 814, 815, 816, 817]	
	
	num = {}
	num["Benign"] = 49	
	num["NTP"] = 54
	num["DNS"] = 2500
	num["LDAP"] = 173
	num["MSSQL"] = 435
	num["NetBIOS"] = 1000
	num["SNMP"] = 122
	num["SSDP"] = 477
	num["UDP"] = 417
	num["SYN"] = 5000
	num["TFTP"] = 51	
	
	for lbl in fs:
		dataset[lbl] = []
		for index in fs[lbl]:
			fname = "Flow_0"+str(index)+".txt"
			print(fname)
			#read file & save num-size dataset
			ctr = 0
			complete = False
			with open(fname, "r") as fr:
				line = fr.readline()
				data = line.split(",")
				while len(data) > 3 and (not complete):	
					#cek is the label is same
					curlbl = data[4][:-1]
					if curlbl == lbl:
						dataset[lbl].append(line)
						ctr +=1
						if ctr >= num[lbl]:
							complete = True
					line = fr.readline()
					data = line.split(",")
		
		with open(foutput, "a") as fo:
			for k in dataset[lbl]:
				#fo.writelines(k+"\n")
				fo.writelines(k)
def genTestingDataset():
	def cekCount(ctrdata, total):
		mytot = 0
		for k in ctrdata:
			mytot += ctrdata[k]
		return total == mytot
	
	for i in range(819):
		fname = "Flow_0"+str(i)+".txt"
		lbldata = {}
		lbldata["Benign"] = []	
		lbldata["NTP"] = []	
		lbldata["DNS"] = []	
		lbldata["LDAP"] = []	
		lbldata["MSSQL"] = []	
		lbldata["NetBIOS"] = []	
		lbldata["SNMP"] = []	
		lbldata["SSDP"] = []	
		lbldata["UDP"] = []	
		lbldata["SYN"] = []	
		lbldata["TFTP"] = []	
		ctrdata = {}
		for k in lbldata:
			ctrdata[k] = 0
		
		print(fname)
		ctr=0
		with open(fname, "r") as fr:
			line = fr.readline()
			data = line.split(",")
			while len(data) > 3:
				
				curlbl = data[4][:-1]
				if curlbl in lbldata:
					lbldata[curlbl].append(line)
					ctrdata[curlbl] +=1
					ctr+=1
				line = fr.readline()
				data = line.split(",")
		if not cekCount(ctrdata, ctr):
			for k in ctrdata:
				print(ctrdata[k])
			input("some error")
			
		
		for k in lbldata:
			if len(lbldata[k]) > 1:
				fout = "withHeader/Flow_0"+str(i)+"_"+k+".txt"		
				with open(fout, "w") as fo:
					fo.writelines("Proto,delta,counter,bytes,label\n")
					for dt in lbldata[k]:
						fo.writelines(dt)

def listAllFile():
	import glob
	files = glob.glob("withHeader/*")
	print(files)
	print(len(files))
	
def genPerlabelDataset(isUnique=False):
	labelstr = ["Benign","NTP","DNS","LDAP","MSSQL","NetBIOS","SNMP","SSDP","UDP","SYN","TFTP"]
	lbldata_unique = {}
	lbldata = {}
	ctrdata = {}
	fout = ""
	#write the header
	if isUnique:
		for lbl in labelstr:
			lbldata_unique[lbl] = set()
			fout = "perLabel/Flow_Unique_"+lbl+".txt"	
			print(fout)
			with open(fout, "w") as fo:
				fo.writelines("Proto,delta,counter,bytes,label\n")

	else:
		for lbl in labelstr:
			lbldata[lbl] = []
			fout = "perLabel/Flow_"+lbl+".txt"
			with open(fout, "w") as fo:
				fo.writelines("Proto,delta,counter,bytes,label\n")

	#loop all dataset
	for i in range(819):	
		fname = "Flow_0"+str(i)+".txt"
		print(fname)
		with open(fname, "r") as fr:
			line = fr.readline()
			data = line.split(",")
			while len(data) > 3:
				curlbl = data[4][:-1]
				if curlbl in labelstr:
					if isUnique:
						lbldata_unique[curlbl].add(line)	
								
					else:
						lbldata[curlbl].append(line)
				#else:
				#	print("!exist")				
				line = fr.readline()
				data = line.split(",")
			#for lbl in labelstr:
			#	if isUnique:
			#		print( len( lbldata_unique[curlbl] ))
			#	else:
			#		print( len( lbldata[curlbl] ))
	if isUnique:
		for lbl in lbldata_unique:
			ctrdata[lbl] = len(lbldata_unique[lbl])
			if len(lbldata_unique[lbl]) > 0:
				fout = "perLabel/Flow_Unique_"+lbl+".txt"	
				with open(fout, "a") as fo:
					for dt in lbldata_unique[lbl]:
						fo.writelines(dt)
	else:
		for lbl in lbldata:
			ctrdata[lbl] = len(lbldata[lbl])
			if len(lbldata[lbl]) > 0:
				fout = "perLabel/Flow_"+lbl+".txt"
				with open(fout, "a") as fo:
					for dt in lbldata[lbl]:
						fo.writelines(dt)
	print("DBcount = {}")
	for lbl in ctrdata:
		print("DBcount[\""+lbl+"\"] = "+str(ctrdata[lbl]))
	
	#uf = {}
	#uf["Benign"] 	=  986433
	#uf["NTP"] 		= 1093973
	#uf["DNS"] 		=   14942
	#uf["LDAP"] 		=  298940
	#uf["MSSQL"] 	=   95149
	#uf["NetBIOS"] 	=   10700
	#uf["SNMP"] 		=  330852
	#uf["SSDP"] 		=  550149
	#uf["UDP"] 		=  641937
	#uf["SYN"] 		=  210050
	#uf["TFTP"] 		= 4027961
	
def genSingleDataset():
	labelstr = ["Benign","NTP","DNS","LDAP","MSSQL","NetBIOS","SNMP","SSDP","UDP","SYN","TFTP"]
	lbldata_unique = {}
	lbldata = {}
	fout = ""
	for lbl in labelstr:
		fout = "perLabel/All_Unique_Flow.txt"	
		with open(fout, "w") as fo:
			fo.writelines("Proto,delta,counter,bytes,label\n")
	
	for lbl in labelstr:
		lbldata[lbl] = []
		lbldata_unique[lbl] = set()
	
	for i in range(819):
		fname = "Flow_0"+str(i)+".txt"
		print(fname)
		with open(fname, "r") as fr:
			line = fr.readline()
			data = line.split(",")
			while len(data) > 3:
				curlbl = data[4][:-1]
				if curlbl in labelstr:
					lbldata_unique[curlbl].add(line)
				line = fr.readline()
				data = line.split(",")
		
	for lbl in lbldata_unique:
		if len(lbldata_unique[lbl]) > 0:
			fout = "perLabel/All_Unique_Flow.txt"	
			with open(fout, "a") as fo:
				for dt in lbldata_unique[lbl]:
						fo.writelines(dt)
						
def genMixDataset(count =10000):
	print("generate mix dataset")
	labelstr = ["Benign","NTP","DNS","LDAP","MSSQL","NetBIOS","SNMP","SSDP","UDP","SYN","TFTP"]
	uf = {}
	DBcount = {}
	DBcount["Benign"] = 143917
	DBcount["NTP"] 	= 544217
	DBcount["DNS"] 	=  14361
	DBcount["LDAP"] 	=  48274
	DBcount["MSSQL"] 	=  15015
	DBcount["NetBIOS"]=   6327
	DBcount["SNMP"] 	=  31172
	DBcount["SSDP"] 	= 141443
	DBcount["UDP"] 	= 138198
	DBcount["SYN"] 	= 209265
	DBcount["TFTP"] 	= 674148
	
	uf["Benign"] 	= min(  count, int( 143917/2) )
	uf["NTP"] 		= min(  count, int( 544217/2) )
	uf["DNS"] 		= min(  count, int(  14361/2) )
	uf["LDAP"] 		= min(  count, int(  48274/2) )
	uf["MSSQL"] 	= min(  count, int(  15015/2) )
	uf["NetBIOS"] 	= min(  count, int(   6327/2) )
	uf["SNMP"] 		= min(  count, int(  31172/2) )
	uf["SSDP"] 		= min(  count, int( 141443/2) )
	uf["UDP"] 		= min(  count, int( 138198/2) )
	uf["SYN"] 		= min(  count, int( 209265/2) )
	uf["TFTP"] 		= min(  count, int( 674148/2) )
	
	for k in uf:
		print(uf[k])
	for lbl in labelstr:
		fout = "perLabel/dataset_"+str(int(count/1000))+"K.txt"	
		with open(fout, "w") as fo:
			fo.writelines("Proto,delta,counter,bytes,label\n")
	
	#read per file, with number: uf[lbl]
	for lbl in labelstr:
		mixDS = []
		fname = "perLabel/Flow_Unique_"+lbl+".txt"
		ctr = 0
		reading = True
		with open(fname, "r") as fr:
			line = fr.readline()
			line = fr.readline()
			
			while (len(line) > 3) and reading:
				mixDS.append(line)
				ctr+=1
				if ctr >= uf[lbl]:
					reading = False
					line = ""
				else:	
					line = fr.readline()
				#print(ctr, line, len(line) > 3, reading)		
					
		with open(fout, "a") as fo:
			for elem in mixDS:
				fo.writelines(elem)
	#save to buffer
	#write to file
	
Menu = """
Menu:
1. Fix dataset's label (X)
2. Count unique dataset(X)
3. Calculate statistic
4. Generate File set
5. Generate Minimal Dataset
6. Generate Normal Dataset
7. Generate Testing Dataset
8. List all testing dataset
9. Generate perLabel Dataset
10. Generate singleDataset
11. Generate mix_Dataset
"""
print(Menu)
option = input("Choose your action:")
if int(option) > 0:
	val = int(option)
	if val == 1:
		for i in range(819):
			relabel(i)	
	elif val == 2:
		#maangeUnique()
		countUnique()
	elif val == 3:
		calcStat()
	elif val == 4:
		genFileset()
	elif val == 5:
		genMinimal()
	elif val == 6:
		genNormal()
	elif val == 7:
		genTestingDataset()
	elif val == 8:
		listAllFile()
	elif val == 9:
		genPerlabelDataset(True)
	elif val == 10:
		genSingleDataset()
	elif val == 11:	
		print("Determine dataset size in Thousand")
		print("e.g 10 --> 10000")
		caption  = "Maximum dataset size ():"
		val = int(input(caption))* 1000
		if val >= 5000 and val <= 100000:	
			genMixDataset(val)
	
	