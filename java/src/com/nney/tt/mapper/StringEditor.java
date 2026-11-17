package com.nney.tt.mapper;

import com.nney.tt.input.KeyEvent;
import com.nney.tt.input.Keyboard;
import com.nney.tt.input.Locks;
import com.nney.utils.Math2;

public class StringEditor {
	private final StringBuilder content;
	private int cx;

	// the scrollable screen is a separate concern that could be pulled out
	private final int screenWidth;
	private int sx;

	class State {
		public final String show;
		public final int cursor;

		State(String show, int cursor) {
			this.show = show;
			this.cursor = cursor;
		}

		@Override
		public String toString() {
			StringBuilder sb = new StringBuilder(show);
			sb.insert(cursor, '_');
			return sb.toString();
		}
	}

	StringEditor(String content, int screenWidth) {
		this.screenWidth = screenWidth;
		this.content = new StringBuilder(content);
		cx = content.length();
	}

	// the key operation of this is a separate concern that could be pulled out
	public void keyboardInput(KeyEvent key) {
		int k = key.keyCode;
		if (k == Keyboard.KEY_HOME) opBegin();
		if (k == Keyboard.KEY_END) opEnd();
		if (k == Keyboard.KEY_LEFT) opLeft();
		if (k == Keyboard.KEY_RIGHT) opRight();
		if (k == Keyboard.KEY_DELETE) opDeleteHere();
		if (k == Keyboard.KEY_BACK) opDeleteBack();
		if (k == Locks.LOCK_CONTROL + Keyboard.KEY_DELETE) opDeleteToEnd();
		if (k == Locks.LOCK_CONTROL + Keyboard.KEY_BACK) opDeleteToStart();
		opType(key.keyChar);
	}

	private void moveCursorTo(int np) {
		cx = Math2.limit(0, content.length(), np);
	}

	public void opType(int c) {
		if (c >= 32) {
			content.insert(cx++, (char) c);
		}
	}

	public void opLeft() {
		moveCursorTo(cx - 1);
	}

	public void opRight() {
		moveCursorTo(cx + 1);
	}

	public void opBegin() {
		moveCursorTo(0);
	}

	public void opEnd() {
		moveCursorTo(Integer.MAX_VALUE);
	}

	public void opDeleteToStart() {
		content.delete(0, cx);
		cx = 0;
	}

	public void opDeleteToEnd() {
		content.delete(cx, content.length());
	}

	public void opDeleteBack() {
		if (cx != 0) {
			cx--;
			content.deleteCharAt(cx);
		}
	}

	public void opDeleteHere() {
		if (cx != content.length()) {
			content.deleteCharAt(cx);
		}
	}

	public State state() {
		int edge = screenWidth - 1;
		if (cx < sx) sx = cx;
		if (cx > sx + edge) sx = cx - edge;

		String show = content.substring(sx, Math.min(content.length(), sx + screenWidth));
		int cursor = cx - sx;
		return new State(show, cursor);
	}

	@Override
	public String toString() {
		return content.toString();
	}
}
