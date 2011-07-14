defined = set()

def q(theirs, ours, def_it):
	global defined
	if def_it:
		if ours in defined: return
		defined.add(ours)
	i = len(defined)
	print "\tstatic final int "+ours+" = "+str(i)+";";

def q2(theirs, ours, def_it):
	if def_it: print "\tadd(org.lwjgl.input.Keyboard."+theirs+", "+ours+");"

def p(theirs, ours=None):
	if ours is None: ours=theirs
	theirs = "KEY_"+theirs
	ours = "KEY_"+ours
	q(theirs, ours, True)

def pb(z):
	z = "KEYBEGIN_"+z
	q(z, z, False)

def pe(z):
	z = "KEYEND_"+z
	q(z, z, False)

def pc(z):
	print
	print "\t// "+z

def list_keys():
	pc("regular keys")
	for c in range(26):
		p(chr(65+c))
	for c in range(10):
		p(chr(48+c))
	for c in range(10):
		p("NUMPAD"+chr(48+c))
	for c in range(1, 13):
		p("F"+str(c))

	pc("cursor keys")
	p("LEFT")
	p("RIGHT")
	p("UP")
	p("DOWN")

	pc("shift keys")
	pb("SHIFTS")
	p("LSHIFT", "SHIFT")
	p("RSHIFT", "SHIFT")
	p("LCONTROL", "CONTROL")
	p("RCONTROL", "CONTROL")
	p("LMENU", "MENU")
	p("RMENU", "MENU")
	pe("SHIFTS")

	pc("round the numeric keypad")
	p("DIVIDE")
	p("MULTIPLY")
	p("SUBTRACT")
	p("ADD")
	#p("RETURN") duplicate!
	p("DECIMAL")

	pc("the navigation cluster")
	p("INSERT")
	p("HOME")
	p("END")
	p("PRIOR")
	p("NEXT")
	p("DELETE")

	pc("main keyboard misc")
	p("ESCAPE")
	p("GRAVE")
	p("MINUS")
	p("EQUALS")
	p("BACK")
	 
	p("TAB")
	p("LBRACKET")
	p("RBRACKET")
	p("RETURN")

	p("SEMICOLON")
	p("APOSTROPHE")
	p("BACKSLASH")

	p("COMMA")
	p("PERIOD")
	p("SLASH")
	p("SPACE")


list_keys()
q = q2
list_keys()
