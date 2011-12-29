package com.nney.tt.tinytools;

public final class SlowBoolean {
	private boolean value;

	public SlowBoolean() {

	}

	public SlowBoolean(boolean b) {
		value = b;
	}

	public boolean set(boolean b) {
		boolean old = value;
		value = b;
		return old;
	}
}
