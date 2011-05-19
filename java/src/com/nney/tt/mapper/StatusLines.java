package com.nney.tt.mapper;

import java.util.TreeMap;

public class StatusLines {
	private TreeMap<Integer, StringBuffer> lines = new TreeMap<Integer, StringBuffer>();
	private int width;
	
	public StatusLines(int width) {
		this.width = width;
	}

	private StringBuffer getOrCreateStringBuffer(int y) {
		StringBuffer l = lines.get(y);
		if (l != null) return l;
		l = new StringBuffer();
		for (int x = 0; x < width; x++)
			l.append(' ');
		lines.put(y, l);
		return l;
	}

	public void put(int x, int y, String t) {
		StringBuffer b = getOrCreateStringBuffer(y);
		int end = x+t.length();
		b.replace(x, end, t);
	}

	public void putLeft(int y, String t) {
		t = notTooBig(t);
		put(0, y, t);
	}

	public void putRight(int y, String t) {
		t = notTooBig(t);
		int x = width - t.length();
		put(x, y, t);
	}

	private String notTooBig(String t) {
		int l = t.length();
		return t.substring(0, Math.min(width, l));
	}

	public String getLine(int y) {
		StringBuffer sb = lines.get(y);
		if (sb==null) return null;
		return sb.toString();
	}
}
