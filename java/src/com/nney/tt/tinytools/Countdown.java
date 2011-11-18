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

	public Countdown run() {
		if (t!=0) t--;
		return this;
	}
	
	public boolean test() {
		return t != 0;
	}
}
