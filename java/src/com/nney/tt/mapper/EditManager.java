package com.nney.tt.mapper;

import com.nney.tt.input.KeyEvent;
import com.nney.tt.mapper.StringEditor.State;
import com.nney.tt.props.Prop;
import com.nney.tt.props.TakeTextBack;

class EditManager {
	private final Prop prop;

	private final StringEditor editor;

	private final TakeTextBack callback;

	private int cursorTimer;

	EditManager(Prop prop, StringEditor editor, TakeTextBack callback) {
		this.prop = prop;
		this.editor = editor;
		this.callback = callback;
	}

	boolean isCursorOn() {
		int rate = 70;
		cursorTimer++;
		cursorTimer %= rate;
		return cursorTimer < (rate * 2 / 3);
	}

	public void keyboardInput(KeyEvent key) {
		cursorTimer = 0;
		editor.keyboardInput(key);
	}

	public void done() {
		callback.take(editor.toString());
	}

	public State state() {
		return editor.state();
	}

	public boolean isUs(Prop p) {
		return p == prop;
	}
}