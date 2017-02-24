import sys
import telnetlib
import threading
import Queue
import time
import subprocess as sub
import pexpect

file = open('/usr/lib/smartwall/tools/miraiCredentials.txt', 'r')
passList = []
for line in file:
	passList.append(line)
global exitFlag
exitFlag = 0

global successState
successState = False

host = str(sys.argv[1])
connectCommand = "telnet " + host
user = "root"


threadList = ["t1", "t2", "t3", "t4", "t5"]

class telThread (threading.Thread):
	def __init__(self, threadID, q):
		threading.Thread.__init__(self)
		self.threadID = threadID
		self.q = q

	def run(self):
		telLogin(self.threadID, self.q)
		

def telLogin(threadName, q):
	while not exitFlag:
		queueLock.acquire()
		if not workQueue.empty():
			data = q.get()
			d = data.split(":")
			queueLock.release()
			
			telconn = pexpect.spawn(connectCommand)
			time.sleep(1)
			telconn.logfile = sys.stdout
			telconn.expect(":")
			time.sleep(1)
			telconn.send(d[0] + "\r")
			telconn.expect(":")
			telconn.send(d[1])
			time.sleep(1)
			telconn.expect(">")
			global successState
			successState = True
			workQueue.queue.clear()
		else:
			queueLock.release()
		time.sleep(1)

queueLock = threading.Lock()
workQueue = Queue.Queue(len(passList))
threads = []
threadID = 1

for thread in threadList:
	thread = telThread(threadID, workQueue)
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