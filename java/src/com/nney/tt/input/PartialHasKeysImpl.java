package com.nney.tt.input;

import java.util.ArrayList;

public abstract class PartialHasKeysImpl implements HasKeys {
	/**
	 * The maximum number of events we queue. Big, but not infinite.
	 */
	private static final int MAX_EVENTS = 2048;

	private ArrayList<KeyEvent> events = new ArrayList<>();

	protected void queueEvent(int k) {
		queueEvent(k, (char) 0);
	}

	protected void queueEvent(int k, char c) {
		if (events.size() < MAX_EVENTS) {
			events.add(new KeyEvent(k, c));
		}
	}

	@Override
	public KeyEvent nextEvent() {
		if (events.isEmpty()) return null;
		return events.remove(0);
	}
}
