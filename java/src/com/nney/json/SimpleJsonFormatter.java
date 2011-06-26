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

	private void put(String s) {
		sb.append(s);
	}

	public void listSep() {
		put(stringListSep);
	}

	public void dictSep() {
		put(stringDictSep);
	}

	public void value(String s) {
		put(s);
	}

	public void beginArray() {
		put(stringArrayBegin);
		term.push(stringArrayEnd);
	}

	public void beginDict() {
		put(stringDictBegin);
		term.push(stringDictEnd);
	}

	public void end() {
		put(term.pop());
	}
	
	public String result() {
		return sb.toString();
	}
}
