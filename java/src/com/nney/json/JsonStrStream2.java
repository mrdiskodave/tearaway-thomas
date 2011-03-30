package com.nney.json;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class JsonStrStream2 {
	private final String s;
	private int p;

	public JsonStrStream2(String s) {
		this.s = s;
		this.p = 0;
	}
	
	public int peek() {
		if (eof()) throw new RuntimeException("overread");
		return s.charAt(p);
	}

	public boolean eof() {
		return p==s.length();
	}
	
	public int read() {
		int answer = peek();
		p++;
		return answer;
	}
	
	public Matcher lookingAt(Pattern pattern) {
		Matcher matcher = pattern.matcher(remains());
		if (!matcher.lookingAt()) return null;
		p = matcher.end();
		return matcher;
	}
	
	public boolean lookingAt(String m) {
		boolean answer = remains().startsWith(m);
		if (answer) p += m.length();
		return answer;
	}
	
	public String remains() {
		return s.substring(p);
	}
}
