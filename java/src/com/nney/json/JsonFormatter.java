package com.nney.json;

public interface JsonFormatter {

	void listSep();

	void dictSep();

	void value(String s);

	void beginArray();

	void beginDict();

	void end();

	String result();

}