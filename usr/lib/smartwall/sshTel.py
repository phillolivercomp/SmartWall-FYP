import sys
import telnetlib
import threading
import Queue
import time
import subprocess as sub
from pexpect import pxssh

file = open('/usr/lib/smartwall/tools/miraiCredentials.txt', 'r')
passList = []
for line in file:
	passList.append(line)
global exitFlag
exitFlag = 0

global successState
successState = False

host = str(sys.argv[1])
user = "root"


threadList = ["t1", "t2", "t3", "t4", "t5"]

class sshThread (threading.Thread):
	def __init__(self, threadID, q):
		threading.Thread.__init__(self)
		self.threadID = threadID
		self.q = q

	def run(self):
		sshLogin(self.threadID, self.q)
		

def sshLogin(threadName, q):
	while not exitFlag:
		queueLock.acquire()
		if not workQueue.empty():
			data = q.get()
			d = data.split(":")
			queueLock.release()
			conn = pxssh.pxssh()
			try:
				conn.login(host, d[0], d[1])
				conn.sendline('echo success')
				conn.prompt()
				conn.logout()
				global successState
				successState = True
				workQueue.queue.clear()
			except pxssh.ExceptionPxssh, e:
				time.sleep(1)
			except pxssh.EOF:
				workQueue.queue.clear()
		else:
			queueLock.release()
		time.sleep(1)

queueLock = threading.Lock()
workQueue = Queue.Queue(len(passList))
threads = []
threadID = 1

for thread in threadList:
	thread = sshThread(threadID, workQueue)
	thread.start()
	threads.append(thread)
	threadID +=1

queueLock.acquire()
for word in passList:
	workQueue.put(word)
queueLock.release()

while not workQueue.empty():
	pass

exitFlag = 1

for t in threads:
	t.join()
print str(successState)