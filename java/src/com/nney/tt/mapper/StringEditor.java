package com.nney.tt.mapper;

import com.nney.tt.input.Keyboard;
import com.nney.tt.input.Locks;
import com.nney.utils.Math2;

public class StringEditor {
	private final StringBuffer content;
	private final int screenWidth;
	private int cx;
	private int sx;
	private boolean bell;
	
	private final KeyMap km;
	private final int margin;
	
	class State {
		public final String show;
		public final int cursor;
		public final boolean bell;

		State(String show, int cursor, boolean bell) {
			this.show = show;
			this.cursor = cursor;
			this.bell = bell;
			
		}
		
		@Override
		public String toString() {
			StringBuffer sb = new StringBuffer(show);
//			System.out.println("SBDO :"+sb+" at "+cursor);
			sb.insert(cursor, '_');
//			System.out.println("SBGOT:"+sb);
			if (bell) sb.append('!');
			return sb.toString();
		}
	}

	StringEditor(String content, int screenWidth, int margin, KeyMap km) {
		this.screenWidth = screenWidth;
		this.margin = margin;
		this.km = km;
		this.content = new StringBuffer(content);
		cx = content.length();
		sx = 0;
	}

	private void moveCursorTo(int np) {
		cx = Math2.limit(0, content.length(), np);
	}

	void keyIn(int k) {
		if (k == Keyboard.KEY_HOME) opBegin();
		if (k == Keyboard.KEY_END) opEnd();
		if (k == Keyboard.KEY_LEFT) opLeft();
		if (k == Keyboard.KEY_RIGHT) opRight();
		if (k == Keyboard.KEY_DELETE) opDeleteHere();
		if (k == Keyboard.KEY_BACK) opDeleteBack();
		if (k == Locks.LOCK_CONTROL + Keyboard.KEY_DELETE) opDeleteToEnd();
		if (k == Locks.LOCK_CONTROL + Keyboard.KEY_BACK) opDeleteToStart();
		
		int c = km.mapKey(k);
		if (c>=0) {
			opType((char)c);
		}
	}

	public void opType(char c) {
		content.insert(cx++, c);
	}

	public void opLeft() {
		if (cx==0) {
			bell();
		}
		else {
			cx--;
		}
	}

	private void bell() {
		bell = true;
	}

	public void opRight() {
		if (cx==content.length()) {
			bell();
		}
		else {
			cx++;
		}
	}

	public void opEnd() {
		moveCursorTo(Integer.MAX_VALUE);
	}

	public void opBegin() {
		moveCursorTo(0);
	}

	public void opDeleteToStart() {
		content.delete(0, cx);
		cx = 0;
	}

	public void opDeleteToEnd() {
		content.delete(cx, content.length());
	}

	public void opDeleteBack() {
		if (cx == 0) {
			bell();
		}
		else {
			cx--;
			content.deleteCharAt(cx);
		}
	}

	public void opDeleteHere() {
		if (cx == content.length()) {
			bell();
		}
		else {
			content.deleteCharAt(cx);
		}
	}
	
	public State state() {
		int edge = screenWidth - 1;
		if (cx<sx) sx = cx;
		if (cx>sx+edge) sx = cx-edge;
		
		System.out.println(content);
		System.out.println(sx);
		
		
		String show = content.substring(sx, Math.min(content.length(), sx+screenWidth));
		int cursor = cx - sx;
		boolean b = bell;
		bell = false;
		return new State(show, cursor, b);
		
		// fabcdefghijk
		// 123456789012
	}
}
