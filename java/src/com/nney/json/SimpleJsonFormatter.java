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

	public void value(String s) {
		put(s);
		put(stringListSep);
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
		strip();
		put(term.pop());
		put(stringListSep);
	}
	
	private void strip() {
		if (endsWith(sb, stringListSep)) {
			sb.setLength(sb.length()-stringListSep.length());
		}
	}

	private boolean endsWith(StringBuilder b, String a) {
		int i = b.length()-a.length();
		if (i<0) {
			return false;
		}
		for (int x=0; x<a.length(); x++) {
			if (a.charAt(x)!=b.charAt(i++)) {
				return false;
			}
		}
		return true;
	}

	public String result() {
		strip();
		return sb.toString();
	}
}
