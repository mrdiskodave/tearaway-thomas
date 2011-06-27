package com.nney.json;

public class StringSafeWriter implements SafeWriter {
	StringBuffer sb = new StringBuffer();
	
	@Override
	public void write(String text) {
		sb.append(text);
	}
	
	@Override
	public String toString() {
		return sb.toString();
	}
}
