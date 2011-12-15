#!/usr/bin/python

#
# I decided that single frame "animations" were a special case
# they didn't need a def.txt of JSON description
# and they didn't need their own folder
#
# This script search out and simplies such structures ...
#

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lib"))

import re
import shelltools

for f in os.listdir('.'):
	content = [ x for x in os.listdir(f) if x.endswith(".png") ]
	if len(content)==1 and content[0]=="000.png":
		print "single frame: "+f
		n = f+".png"
		shelltools.Cmd.shellf("cp {0} {1}", os.path.join(f, "000.png"), n).check_call()
		shelltools.Cmd.shellf("svn rm {0}", f).check_call()
		shelltools.Cmd.shellf("svn add {0}", n).check_call()


