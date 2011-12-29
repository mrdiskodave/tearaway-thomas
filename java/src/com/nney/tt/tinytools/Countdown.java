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

	public void run() {
		if (t != 0) t--;
	}

	public boolean test() {
		return t != 0;
	}

	public boolean testAndRun() {
		if (t == 0) return false;
		t--;
		return true;
	}

}
