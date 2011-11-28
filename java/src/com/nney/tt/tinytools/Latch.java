package com.nney.tt.tinytools;

/**
 * Sometimes you want to do something as long as you haven't already done it
 * last frame (or this frame). Only when the agent stops trying to do it does it
 * become possible again.
 */
public final class Latch {
	private int last;
	private int tolerance;

	public Latch(int tolerance) {
		clear();
		this.tolerance = tolerance;
	}

	public Latch() {
		this(1);
	}

	public boolean can(int now) {
		boolean answer = test(now);
		last = now;
		return answer;
	}

	private boolean test(int now) {
		int diff = now - last;
		// System.out.println(String.format("test:now%s last%s diff%s", now,
		// last, diff));
		return diff > tolerance;
	}

	public void set(int now) {
		// System.out.println("set:now"+now);
		last = now;
	}

	public void clear() {
		// initial value so that can(0) returns true
		last = -10;
	}
}
