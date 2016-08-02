#!/usr/bin/python
import sys, re, os
from pexpect import pxssh
sys.path.insert(0, '/Library/Developer/CommandLineTools/Library/PrivateFrameworks/LLDB.framework/Resources/Python')
import lldb

class SshClient(object):
	def __init__(self, hostname='127.0.0.1', port=22, username='root', password='', options={"StrictHostKeyChecking":"no"}, add_options={}):
		self.s = s = pxssh.pxssh()
		options.update(add_options)
		s.options = options
		print "Connecting via SSH to %s@%s" % (username,hostname)
		if not s.login(server=hostname, username=username, password=password, port=port):
			raise RuntimeError("Invalid SSH connection or credentials")
		print "Successfully connected via SSH"

	def execCommand(self, cmd):
		s = self.s
		# clean files
		s.sendline('echo -n "" 2> /tmp/stderr > /tmp/stdout')
		s.prompt()
		# exec command
		s.sendline('%s 2> /tmp/stderr > /tmp/stdout' % cmd )
		s.prompt()
		# retrieve return code
		s.sendline('echo $?')
		s.prompt()
		try:
			self.retcode = int(s.before.split('\n',1).pop(1).strip())
		except:
			self.retcode = None
		# retrieve stdout
		s.sendline('cat /tmp/stdout')
		s.prompt()
		self.stdout = s.before.split('\n',1).pop(1)
		# retrieve stderr
		s.sendline('cat /tmp/stderr')
		s.prompt()
		self.stderr = s.before.split('\n',1).pop(1)
		return (self.stdout,self.stderr)

def findPidByName(ssh,name):
	ssh.execCommand('ps -ef | grep /var/mobile/ | grep /Application/ | grep %s' % repr(name))
	if ssh.retcode != 0:
		raise RuntimeError("Can't find process by name: %s" % repr(name))
	pids = [int(line.split()[1]) for line in ssh.stdout.splitlines()]
	if len(pids) != 1:
		raise RuntimeError("Can't decide between pids %s for name %s" % (pids,repr(name)))
	print "Found PID for process name '%s': %d" % (name,pids[0])
	return pids[0]

procExpInstalled = False
def installProcExpIfNeeded(ssh):
	global procExpInstalled
	if procExpInstalled:
		return
	ssh.execCommand('find /tmp/ -maxdepth 1 -type f -name procexp.universal -perm +111')
	if ssh.stdout:
		return
	print "Installing procexp"
	url = "http://web.archive.org/web/20160406180403/http://newosxbook.com/tools/procexp.tgz"
	ssh.execCommand('wget -O /tmp/procexp.tgz %s' % repr(url))
	if ssh.retcode != 0:
		raise RuntimeError("Can't download procexp from %s" % url)
	ssh.execCommand('tar xf /tmp/procexp.tgz -C /tmp/ procexp.universal')
	if ssh.retcode != 0:
		raise RuntimeError("Can't extract procexp.universal from /tmp/procexp.tgz")
	ssh.execCommand('chmod 777 /tmp/procexp.universal')
	if ssh.retcode != 0:
		raise RuntimeError("Can't chmod procexp.universal from /tmp/procexp.tgz")
	print "Procexp installed successfully"
	procExpInstalled = True

def listRegionsWithProcExp(ssh,pid):
	installProcExpIfNeeded(ssh)
	cmd = "/tmp/procexp.universal %d regions | grep -i malloc | grep -iv -e metadata -e guard -e NUL" % pid
	ssh.execCommand( cmd )
	if ssh.retcode != 0:
		raise RuntimeError("Invalid PID %d" % pid)
	regions = re.findall(r'\s([\da-f]+)-([\da-f]+)\s',ssh.stdout)
	regions = [(hex(int(start,16)),hex(int(end,16))) for (start,end) in regions]
	print "Found %d memory regions to dump (%d Mb total)" % (len(regions),sum(map(lambda (x,y):int(y,16)-int(x,16),regions))/1024.0/1024)
	return regions

debugServerInstalled = False
def installDebugServerIfNeeded(ssh):
	global debugServerInstalled
	if debugServerInstalled:
		return
	ssh.execCommand('find /tmp/ -maxdepth 1 -type f -name debugserver -perm +111')
	if ssh.stdout:
		return
	print "Installing debugserver"
	url = "https://raw.githubusercontent.com/heardrwt/ios-debugserver/master/7.0/debugserver"
	ssh.execCommand('wget -O /tmp/debugserver %s' % repr(url))
	if ssh.retcode != 0:
		raise RuntimeError("Can't download debugserver from %s" % url)
	ssh.execCommand('chmod 777 /tmp/debugserver')
	if ssh.retcode != 0:
		raise RuntimeError("Can't chmod /tmp/debugserver")
	print "Debugserver installed successfully"
	debugServerInstalled = True

def dumpRegionsByPid(ssh,pid):
	installProcExpIfNeeded(ssh)
	regions = listRegionsWithProcExp(ssh,pid)
	installDebugServerIfNeeded(ssh)
	print "Attaching debugserver to PID %d" % (pid,)
	ssh.execCommand('/tmp/debugserver *:4567 --attach %d & #' % pid)
	ssh.execCommand('jobs')
	if not ssh.stdout:
		print ssh.retcode,ssh.stdout,ssh.stderr
		raise RuntimeError("Can't run /tmp/debugserver")
	dumpRegionsWithLLDB(regions)

def dumpRegionsByProcessName(ssh,process_name):
	pid = findPidByName(ssh,process_name)
	dumpRegionsByPid(ssh,pid)

def dumpRegions(ssh,pidOrProcName):
	if str(pidOrProcName).isdigit():
		dumpRegionsByPid(ssh,pidOrProcName)
	else:
		dumpRegionsByProcessName(ssh,pidOrProcName)

def dumpRegionsWithLLDB(regions):
	print "Starting LLDB locally"
	dbg = lldb.SBDebugger.Create()
	dbg.SetAsync(False)

	cmd = dbg.GetCommandInterpreter()
	res = lldb.SBCommandReturnObject()

	cmd.HandleCommand("platform select remote-ios",res)
	print res.GetOutput().strip()

	print "Connecting to remote process"
	cmd.HandleCommand("process connect connect://127.0.0.1:4567",res)
	print res.GetOutput().strip()

	for idx, (start_region, end_region) in enumerate(regions):
		filename = "%s-%s.bin" % (start_region[2:],end_region[2:])
		size = int(end_region,16) - int(start_region,16)
		if os.path.exists(filename) and size == os.path.getsize(filename):
			continue
		print "%3d - Dumping memory area %s - %s (%d Kb)" % (idx,start_region,end_region,size/1024.0)
		cmd.HandleCommand('memory read --force --binary --outfile "%s" %s %s' % (filename,start_region,end_region),res)
		print res.GetOutput().strip()

if __name__ == "__main__":
	(password,port,pidOrProcName) = sys.argv[1:4]
	ssh = SshClient(port=port,password=password,add_options={'PubkeyAuthentication':'no','LocalForward':'4567 127.0.0.1:4567'})
	dumpRegions(ssh, pidOrProcName)
