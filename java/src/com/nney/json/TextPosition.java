package com.nney.json;

class TextPosition {
	final int x;
	final int y;

	TextPosition(int x, int y) {
		this.x = x;
		this.y = y;
	}

	static TextPosition fromText(String text) {
		int x = 0;
		int y = 0;
		for (int j = 0; j < text.length(); j++) {
			x++;
			if (text.charAt(j) == '\n') {
				x = 0;
				y++;
			}
		}
		return new TextPosition(x + 1, y + 1);
	}

	@Override
	public String toString() {
		return y + ":" + x;
	}
}
