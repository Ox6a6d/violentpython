#!/usr/local/bin/python3

import optparse
from socket import *
from threading import * 

screenLock = Semaphore(value=1)
def connScan(tgtHost,tgtPort) :
	try:
		connSkt = socket(AF_INET, SOCK_STREAM)
		connSkt.connect((tgtHost,tgtPort))
		#connSkt.send('ViolentPython\r\n')
		#results=connSkt.recv(100)
		screenLock.acquire()
		#print(results)
		print('[+] :{0}/tcp open'.format(tgtPort))
	except:
		screenLock.acquire()
		print('[-] {0}/tcp closed'.format(tgtPort))
	finally: 
		screenLock.release()
		connSkt.close()

def portScan(tgtHost,tgtPorts):
	try:
		tgtIP = gethostbyname(tgtHost)
	except :
		print('[-] Cannot resolve {0} : Unknown host'.format(tgtHost))
		return
	
	try:
		tgtName = gethostbyaddr(tgtIP)
		print('\n[+] Scan results for:' + tgtName[0])
	except:
		print('\n[+] Scan results for:' + tgtIP)

	setdefaulttimeout(1)

	for tgtPort in tgtPorts :
		print('Scanning Port ' + tgtPort)
		t = Thread(target=connScan, args=(tgtHost, int(tgtPort)))
		t.start()
		#connScan(tgtHost, int(tgtPort))

def main() :
	parser = optparse.OptionParser("usageprog" + "-H <target host> -p <target port>")
	parser.add_option('-H',dest='tgtHost', type='string', help='specify target host')
	parser.add_option('-p', dest='tgtPort', type='string', help='specify target port[s] separated by comma')
	(options,args) = parser.parse_args()
	tgtHost=options.tgtHost
	tgtPorts=str(options.tgtPort).split(',')
	print(tgtPorts)
	if (tgtHost==None) | (tgtPorts[0] == None) :
		print("[-] You must specify a target host and port[s]")
		exit(0)
	portScan(tgtHost, tgtPorts)

if __name__ == '__main__' :
    main()

