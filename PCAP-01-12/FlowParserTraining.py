from networkx.algorithms import bipartite
import networkx as nx
import sys, binascii
from scapy.all import *

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

pktDB = {}
flowDB = {}
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

def getLabel(start, end):	
	for k in tsdata:
		#if start > 1543620900:
		#	print(tsdata[k], start, end)
		#	print(start > tsdata[k][0] and start < tsdata[k][1] )
		#	print( end > tsdata[k][0] and end < tsdata[k][1])
		#	
		#	input("...")
		if (start > tsdata[k][0] and start < tsdata[k][1]) or ( end > tsdata[k][0] and end < tsdata[k][1]):
			return k

	return "Benign"
	#if (start > 1541248980 and start < 1541249460) or ( end > 1541248980 and end < 1541249460):
	#	return  "PortMap"
	#if (start > 1541250000 and start < 1541250540) or ( end > 1541250000 and end < 1541250540):
	#	return  "NetBIOS"
	#if (start > 1541251260 and start < 1541251800) or ( end > 1541251260 and end < 1541251800):
	#	return  "LDAP"
	#if (start > 1541251980 and start < 1541252520 ) or ( end > 1541251980 and end < 1541252520 ):
	#	return  "MSSQL"                                          
	#if (start > 1541253180 and start < 1541253780 ) or ( end > 1541253180 and end < 1541253780 ):
	#	return  "UDP"                                            
	#if (start > 1541254440 and start < 1541255040 ) or ( end > 1541254440 and end < 1541255040 ):
	#	return  "UDP-Lag"                                        
	#if (start > 1541255280 and start < 1541256660 ) or ( end > 1541255280 and end < 1541256660 ):
	#	return  "SYN"
	#return "Benign"
def saveStats(data):
	with open("stateful/stats.csv","a") as fw:
		fw.write(",".join(data)+"\n")
	print("stat updated")
class Flow():
	def __init__(self, FID, proto, time, bytectr):#pktID, 
		self.fid = FID
		#self.pid = pktID
		self.state = 0
		""" dft = 0, syn =1
		rst = 0
		finA-1 = 2,
		finB-1 = 3,
		ack-3 = 0
		"""
		self.proto = proto
		self.ftime = time
		self.ltime = time
		self.dtime = 0
		self.dtime2 = 0
		self.pktctr = 1
		self.bytectr = bytectr
		self.findst = 0
		self.label = "Benign"
	def update(self, time, bytectr):
		self.dtime2 = time - self.ltime
		self.ltime = time
		self.dtime = self.ltime - self.ftime
		self.pktctr +=1
		self.bytectr += bytectr
	def getData(self):
		self.label = getLabel(self.ftime, self.ltime)
		return [self.fid, self.proto, str(self.ftime), str(self.dtime), str(self.pktctr), str(self.bytectr), self.label, str(self.state)]
		
class FlowManager():
	def __init__(self):
		self.flist = {}
		self.fctr = {}
	def update(self, pid, proto, flag, data):
		spid = ""
		if pid[0] > pid[1]:
			spid = pid[0] +"-"+ pid[1]
		else:
			spid = pid[1] +"-"+ pid[0]
		dst = pid[1]
		if not(spid in self.fctr):
			self.fctr[spid] = 0
		fid = spid +"#"+ str( self.fctr[spid] )
		if not(fid in self.flist):
			flow = Flow(fid, proto, data[0], data[1])
			self.flist[fid] = flow
		else:
			self.flist[fid].update(data[0], data[1])
		
		curFlow = self.flist[fid]
		if flag == 1:#syn
			curFlow.state = 1
		elif flag == 2:#rst
			curFlow.state = 2
			self.fctr[spid] +=1
		elif flag == 3 and curFlow.state >= 1:#fin
			if curFlow.findst == 0:
				curFlow.findst = dst
				curFlow.state = 2
			else:
				curFlow.state = 3
		elif flag == 4 and curFlow.state == 3: #ack
			curFlow.state = 4
			self.fctr[spid] +=1
		#if self.fctr[spid] == 1:
		#	print(curFlow.fid,flag,curFlow.state)
	def saveFlow(self, pcapname):
		fname = pcapname.split("_")[1]
		flowdata = self.flist
		print("flow entries:",len(flowdata))
		flowDB[pcapname] = len(flowdata)
		saveStats(["flowstat[\""+pcapname+"\"] = "+str(len(flowdata))])
		print("saving...")
		with open("stateful/Flow_"+fname+".csv","w") as fw:
			for i in flowdata:
				entry = ",".join(flowdata[i].getData())
				fw.write(entry+"\n")
		print("saved")

def pcapReader(pcapname, period=0 ):
	print("extracting ",pcapname)
	FM = FlowManager()
	
	ctr = 0
	first = True
	for pkt in PcapReader(pcapname):
		
		time = pkt.time - 14400
		if first:
			first = False
			print("Start",time, datetime.utcfromtimestamp(int(time)))
		if IP in pkt:#version, ihl, tos, len, id, flags, frag, ttl, proto, src, dst
			ipproto = str(pkt['IP'].proto)
			isIP = 4
			srcIP = str(pkt['IP'].src).replace(".","_")
			dstIP = str(pkt['IP'].dst).replace(".","_")
			#byte = pkt['IP'].len
		elif IPv6 in pkt:	#version, tc, fl, plen, nh, hlim
			isIP = 6
			ipproto = str(pkt['IPv6'].nh)
			srcIP = str(pkt['IPv6'].src)
			dstIP = str(pkt['IPv6'].dst)
			#byte = pkt['IPv6'].plen
		else:
			isIP = 0
		if isIP>0:
			if TCP in pkt:
				F = pkt['TCP'].flags    #integer
				pktflag = 0
				if F & SYN:
					pktflag = 1
				if F & RST:
					pktflag = 2
				if F & FIN:
					pktflag = 3
				if F & ACK:
					pktflag = 4
				
				sPort = str(pkt['TCP'].sport)
				dPort = str(pkt['TCP'].dport)
				A = srcIP +":"+ sPort
				B = dstIP +":"+ dPort
				protobyte = pkt['IP'].len
				FM.update([A, B], ipproto, pktflag, [time, protobyte])

			elif UDP in pkt:
				pktflag = 0
				sPort = str(pkt['UDP'].sport)
				dPort = str(pkt['UDP'].dport)
				A = srcIP +":"+ sPort
				B = dstIP +":"+ dPort
				protobyte = pkt['UDP'].len
				proto = B
				
				FM.update([A, B], ipproto, 0, [time, protobyte])
			else:
				pass#print(pkt.summary())
		ctr+=1
		if ctr % 10000 == 0:
			print("pkt-",ctr)
			#break
	print("End",time, datetime.utcfromtimestamp(int(time)))
	
	print(pcapname, "| total packets: ",ctr )
	pktDB[pcapname] = ctr
	#saveStats([pcapname,"packet",str(ctr)])
	saveStats(["pktstat[\""+pcapname+"\"] = "+str(ctr)])
	FM.saveFlow(pcapname)

if __name__ == "__main__":
	a,b = int(sys.argv[1]), int(sys.argv[2])
	for i in range(a,b):
		#pcapReader(sys.argv[1])
		pcapReader("SAT-01-12-2018_0"+str(i))
		
		print("stats")
		print(pktDB)
		print(flowDB)
	#packet size: 27 GB pcap file
	#flow size	: 1.5 GB of flow data	
	#file 1
	#pkt: 511063 pktdata, 189154
	#f1: 14 MB
	
	#packet size: 152 GB training data
	#flow size	: 3.87 GB
	
	