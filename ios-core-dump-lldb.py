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

def getCoreDumpWithLLDB(ssh, pidOrProcName):
	if not str(pidOrProcName).isdigit():
		pid = findPidByName(ssh,pidOrProcName)
	else:
		pid = pidOrProcName
	installDebugServerIfNeeded(ssh)
	print "Attaching debugserver to PID %d" % (pid,)
	ssh.execCommand('/tmp/debugserver *:4567 --attach %d & #' % pid)
	ssh.execCommand('jobs')
	if not ssh.stdout:
		print ssh.retcode,ssh.stdout,ssh.stderr
		raise RuntimeError("Can't run /tmp/debugserver")

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

	print "Getting core dump with LLDB"
	cmd.HandleCommand('process save-core "core.%d"' % (pid))
	print res.GetOutput().strip()

if __name__ == "__main__":
	(password,port,pidOrProcName) = sys.argv[1:4]
	ssh = SshClient(port=port,password=password,add_options={'PubkeyAuthentication':'no','LocalForward':'4567 127.0.0.1:4567'})
	getCoreDumpWithLLDB(ssh, pidOrProcName)