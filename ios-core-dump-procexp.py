#!/usr/bin/python
import sys, re, os, pexpect
from pexpect import pxssh

class SshClient(object):
	def __init__(self, hostname='127.0.0.1', port=22, username='root', password='', options={"StrictHostKeyChecking":"no"}, add_options={}):
		self.s = s = pxssh.pxssh()
		options.update(add_options)
		s.options = options
		print "Connecting via SSH to %s@%s" % (username,hostname)
		if not s.login(server=hostname, username=username, password=password, port=port):
			raise RuntimeError("Invalid SSH connection or credentials")
		print "Successfully connected via SSH"
		self.username = username
		self.password = password
		self.hostname = hostname
		self.port = int(port)
		self.options = options

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

	def scpGetFile(self, src, dst):
		self.execCommand('stat --printf="%%s\\n" %s' % repr(src))
		if self.retcode != 0:
			raise RuntimeError('File %s not found on device' % repr(src))
		size = int(self.stdout)
		remote_src = "%s@%s:%s" % (self.username,self.hostname,src)
		options = '-o %s' % ','.join(map(lambda (x,y):"%s:%s" % (x,y),self.options.items())) if self.options else ''
		scp = pexpect.spawn('scp -P %d %s %s %s' % (self.port,options,repr(remote_src),repr(dst)))
		ret = scp.expect(["password:", pexpect.EOF])
		if ret == 0:
			scp.sendline(self.password)
			scp.expect(pexpect.EOF)
		scp.close()
		if not os.path.exists(dst):
			raise RuntimeError('Transfer failed: local file %s not found' % repr(dst))
		local_size = os.path.getsize(dst)
		if local_size != size:
			raise RuntimeError('Size of fetched file %s differs from expected' % repr(src))

	def scpPutFile(self, src, dst):
		if not os.path.exists(src):
			raise RuntimeError('Local file %s not found' % repr(src))
		local_size = os.path.getsize(src)
		remote_dst = "%s@%s:%s" % (self.username,self.hostname,dst)
		options = '-o %s' % ','.join(map(lambda (x,y):"%s:%s" % (x,y),self.options.items())) if self.options else ''
		scp = pexpect.spawn('scp -P %d %s %s %s' % (self.port,options,repr(src),repr(remote_dst)))
		ret = scp.expect(["password:", pexpect.EOF])
		if ret == 0:
			scp.sendline(self.password)
			scp.expect(pexpect.EOF)
		scp.close()
		self.execCommand('stat --printf="%%s\\n" %s' % repr(dst))
		if self.retcode != 0:
			raise RuntimeError('Transfer failed: remote file %s not found' % repr(dst))
		size = int(self.stdout)
		if local_size != size:
			raise RuntimeError('Size of fetched file %s differs from expected' % repr(src))

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

def getCoreDump(ssh,pidOrProcName):
	if not str(pidOrProcName).isdigit():
		pid = findPidByName(ssh,pidOrProcName)
	else:
		pid = pidOrProcName
	ssh.execCommand('rm /tmp/core.%d' % pid)
	print "Getting core dump with procexp"
	ssh.execCommand('/tmp/procexp.universal %d core' % pid)
	ssh.scpGetFile('/tmp/core.%d' % pid, 'core.%d' % pid)

if __name__ == "__main__":
	(password,port,pidOrProcName) = sys.argv[1:4]
	ssh = SshClient(port=port,password=password,add_options={'PubkeyAuthentication':'no','LocalForward':'4567 127.0.0.1:4567'})
	getCoreDump(ssh,pidOrProcName)