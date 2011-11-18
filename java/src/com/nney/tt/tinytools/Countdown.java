package com.nney.tt.tinytools;

public final class Countdown {
	private int t;

	public Countdown() {
	}

	public Countdown(int x) {
		t = x;
	}

	public void set(int x) {
		t = x;
	}

	public boolean testAndDec() {
		if (t == 0) return false;
		t--;
		return true;
	}

	public boolean test() {
		return t != 0;
	}
}
