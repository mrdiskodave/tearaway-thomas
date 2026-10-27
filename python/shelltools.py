#!/usr/bin/python

from __future__ import division
from __future__ import with_statement

import StringIO
import pipes
import subprocess
import re

debug_hook = None

def set_debug_hook(l):
	global debug_hook
	debug_hook = l

def shell_esc(s):
	assert isinstance(s, basestring), type(s)
	#print "before"+repr(s)
	s = pipes.quote(s)
	#print "after"+repr(s)
	return s

class Result(object):
	def __init__(self, stdout, stderr, returncode, cmd):
		self.stdout = stdout
		self.stderr = stderr
		self.returncode = returncode
		self.cmd = cmd

	def check(self):
		if self.returncode:
			self.raise_error()
		return self

	def raise_error(self, rc=None):
		if rc is None: rc = self.returncode
		raise subprocess.CalledProcessError(rc, unicode(self.cmd))

	def stdout_lines(self):
		return self.stdout.splitlines()

	def stderr(self):
		return self.stderr.splitlines()

class Cmd(object):
	def __init__(self, cmd, shell):
		self._cmd = cmd
		self._shell = shell

	@staticmethod
	def shell(s):
		assert isinstance(s, basestring)
		return Cmd(s, True)

	@staticmethod
	def shellf(t, *args):
		assert isinstance(t, basestring)

		def safe_get_arg(args, idx):
			assert idx<len(args)
			assert idx>=0
			return args[idx]

		return Cmd.shell(re.sub(r"{(\d+)}", lambda m: shell_esc(unicode(safe_get_arg(args, int(m.group(1))))), t))

	@staticmethod
	def args(*s):
		assert isinstance(s, tuple)
		assert len(s)
		assert isinstance(s[0], basestring)
		return Cmd(s, False)

	def is_shell(self):
		return self._shell

	def check_call(self, input=None):
		return self.do(input=input).check()

	def call(self, input=None):
		return self.do(input=input).returncode

	def do(self, input=None, stdout=False, stderr=False, both=False):
		if debug_hook:
			debug_hook(self._cmd)
		if both:
			stdout = True
			stderr = True
		o = subprocess.PIPE if stdout else None
		e = subprocess.PIPE if stderr else None
		s = subprocess.Popen(self._cmd, stdin=subprocess.PIPE, stdout=o, stderr=e, shell=self.is_shell())
		stdout_text, stderr_text = s.communicate(input)

		# is this already the case?
		if not stdout: stdout_text = None
		if not stderr: stderr_text = None

		rc = s.returncode
		return Result(stdout_text, stderr_text, rc, self)

	def __unicode__(self):
		if self.is_shell():
			return self._cmd
		else:
			return ' '.join([ shell_esc(x) for x in self._cmd])

	def __str__(self):
		return unicode(self).encode('utf-8')

if __name__ == "__main__":
	for s in Cmd.shellf("ls {0}", ".").do(stdout=True).check().stdout_lines():
		print "1>>>", s

	for s in Cmd.shell("cat").do(input="hello", stdout=True).check().stdout_lines():
		print "2>>>", s

	for s in Cmd.args("ls", 'lard').do(stdout=True).check().stdout_lines():
		print "3>>>", s

