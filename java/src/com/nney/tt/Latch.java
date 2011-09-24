package com.nney.tt;

/**
 * Sometimes you want to do something as long as you haven't already done it
 * last frame (or this frame). Only when the agent stops trying to do it does it
 * become possible again.
 */
public class Latch {
	private int last;

	public boolean can(int now) {
		int diff = now - last;
		set(now);
		return diff > 1;
	}

	public void set(int now) {
		last = now;
	}

	public void clear() {
		last = 0;
	}
}
