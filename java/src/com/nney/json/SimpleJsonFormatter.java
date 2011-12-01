package com.nney.json;

import java.util.Stack;

public class SimpleJsonFormatter {
	public String stringListSep = ",";
	public String stringDictSep = ":";
	public String stringArrayBegin = "[";
	public String stringArrayEnd = "]";
	public String stringDictBegin = "{";
	public String stringDictEnd = "}";
	private final SafeWriter sw;

	SimpleJsonFormatter(SafeWriter sw) {
		this.sw = sw;
	}

	private Stack<String> term = new Stack<String>();
	private boolean sepNext;

	public void spaciousBrackets() {
		stringArrayBegin = "[ ";
		stringArrayEnd = " ]";
		stringDictBegin = "{ ";
		stringDictEnd = " }";
	}

	public void spaciousSeperators() {
		stringListSep = ", ";
		stringDictSep = ": ";
	}

	private void put(String s) {
		if (sepNext) {
			sw.write(stringListSep);
			sepNext = false;
		}
		makeOutput(s);
	}

	protected void makeOutput(String s) {
		sw.write(s);
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
		value(term.pop());
	}

	protected int depth() {
		return term.size();
	}
}
