package com.nney.tt.input;

import java.util.ArrayList;

public abstract class PartialHasKeysImpl implements HasKeys {
	private ArrayList<KeyEvent> events = new ArrayList<KeyEvent>();

	protected void queueEvent(int k) {
		queueEvent(k, (char) 0);
	}

	protected void queueEvent(int k, char c) {
		events.add(new KeyEvent(k, c));
	}

	@Override
	public KeyEvent nextEvent() {
		if (events.isEmpty()) return null;
		return events.remove(0);
	}
}
