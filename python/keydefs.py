i = 1;

def q(z, i):
	print "\tstatic final int "+z+" = "+str(i)+";";

def q2(z, i):
	if i: print "\tadd(org.lwjgl.input.Keyboard."+z+", "+z+");"

def p(z):
	global i
	q("KEY_"+z, True)
	i += 1;

def pb(z):
	q("KEYBEGIN_"+z, False)

def pe(z):
	q("KEYEND_"+z, False)

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
	pb("SHIFT_KEYS");
	p("LSHIFT")
	p("RSHIFT")
	p("LCONTROL")
	p("RCONTROL")
	p("LMENU")
	p("RMENU")
	pe("SHIFT_KEYS");

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
