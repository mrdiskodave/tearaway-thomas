package com.nney.tt.mapper;

/**
 * A counter that goes up and down forever, a "triangle wave":
 * 0, 1, ..., top - 1, top, top - 1, ..., 1, 0, 1, ...
 * <p>
 * Each step takes {@code scale / rate} calls to {@link #advance()} (which
 * needn't be a whole number), so a slow cycle can be driven once a frame. A
 * whole cycle, up and back down, is {@code 2 * top} steps.
 * <p>
 * The mapper uses one, through {@link ColorCycler}, to pulse its highlights.
 */
public class Cycle {
	/** The highest value. */
	private final int top;
	/** Where we are in the cycle, in units of 1/scale of a step. */
	private int x;
	/** How many units of x make one step. */
	private final int scale;
	/** How many units of x each {@link #advance()} moves on. */
	private final int rate;
	/** Steps in a whole cycle, up and back down. */
	private int length;

	/**
	 * @param top the highest value (the lowest is 0)
	 * @param scale the units each step is split into
	 * @param rate the units each {@link #advance()} moves on: less than
	 *            {@code 2 * top * scale}, a whole cycle
	 */
	Cycle(int top, int scale, int rate) {
		if (top <= 0 || scale <= 0 || rate <= 0) {
			throw new IllegalArgumentException();
		}
		this.top = top;
		this.scale = scale;
		this.rate = rate;
		this.length = top * 2;
	}

	/** One step per {@link #advance()}. */
	Cycle(int top) {
		this(top, 1, 1);
	}

	/** @return the {@link #current()} value, then {@link #advance()}s */
	int next() {
		int answer = current();
		advance();
		return answer;
	}

	/** @return the value now, from 0 to top */
	int current() {
		int answer = x / scale;
		// steps after top come back down
		if (answer > top) {
			answer = 2 * top - answer;
		}
		return answer;
	}

	/** Moves on by rate/scale of a step, going round at the end of a cycle. */
	void advance() {
		x += rate;
		if (x >= length * scale) {
			x -= length * scale;
		}

	}
}
