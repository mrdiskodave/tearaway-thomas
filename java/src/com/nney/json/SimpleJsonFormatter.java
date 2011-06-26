package com.nney.json;

import java.util.Stack;

public class SimpleJsonFormatter {
	public String stringListSep = ", ";
	public String stringDictSep = ": ";
	public String stringArrayBegin = "[ ";
	public String stringArrayEnd = " ]";
	public String stringDictBegin = "{ ";
	public String stringDictEnd = " }";

	private StringBuilder sb = new StringBuilder();
	private Stack<String> term = new Stack<String>();
	private boolean sepNext; 

	private void put(String s) {
		if (sepNext) {
			sb.append(stringListSep);
			sepNext = false;
		}
		sb.append(s);
	}

	public void value(String s) {
		put(s);
		sepNext = true;
	}

	public void beginArray() {
		put(stringArrayBegin);
		term.push(stringArrayEnd);
	}

	public void beginDict() {
		put(stringDictBegin);
		term.push(stringDictEnd);
	}

	public void key(String s) {
		put(s);
		put(stringDictSep);
	}

	public void end() {
		sepNext = false;
		put(term.pop());
		sepNext = true;
	}
	
	public String result() {
		return sb.toString();
	}
}
