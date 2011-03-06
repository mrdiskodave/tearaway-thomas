package com.nney;


public class Anim {
	static int STOP = Integer.MAX_VALUE;
	
	/**
	 * The animation rate from 256 (every frame) to 1 (every 256 frames) to 0
	 * (never).
	 */
	int configuredRate;

	/**
	 * Where we are in the frame list.
	 */
	int pos;

	/**
	 * Accumulator used to track how far rate progression towards next frame.
	 */
	int acc;

	/**
	 * The frames themselves.
	 */
	Bob[] frames;

	private final int continueFrom;
	
	Bob next() {
		acc += configuredRate;
		if (acc>256) {
			acc -= 256;
			pos += 1;
			if (pos>=frames.length) {
				pos = continueFrom;
				if (continueFrom==STOP) {
					pos = frames.length-1;
				}
			}
		}
		return frames[pos];
	}

	Anim(int rate, Bob[] frames, int continueFrom) {
		this.configuredRate = rate;
		this.frames = frames;
		this.continueFrom = continueFrom;
	}
	
	Anim(int rate, Bob[] frames) {
		// by default -- a looping animation
		this(rate, frames, 0);
	}
}
