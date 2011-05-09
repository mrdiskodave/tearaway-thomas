i = 1;

def q(z):
	print "\tstatic final int "+z+" = "+str(i)+";";

def q2(z):
	print "\tcase org.lwjgl.input.Keyboard."+z+": return "+z+";"

def p(z):
	global i
	q("KEY_"+z)
	i += 1;

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
	p("LSHIFT")
	p("LCONTROL")
	p("LMENU")
	p("RMENU")
	p("RCONTROL")
	p("RSHIFT")

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
