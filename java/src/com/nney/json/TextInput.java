package com.nney.json;

public class TextInput {
	private int pos;

	private String text;

	private boolean more() {
		return pos < text.length();
	}

	TextInput(String mySource) {
		assert mySource!=null;
		this.text = mySource;
	}

	void back() {
		if (pos > 0) {
			pos--;
		}
	}

	char next() {
		if (more()) {
			char c = text.charAt(pos);
			pos++;
			return c;
		}
		return 0;
	}

	public String reportPosition() {
		return " at character " + pos + " of " + text;
	}
}
