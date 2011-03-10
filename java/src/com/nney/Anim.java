package com.nney;

public class Anim {
	/**
	 * The animation rate from 256 (every frame) to 1 (every 256 frames) to 0
	 * (never).
	 */
	int rate;

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
	Bob[] bobs;

	boolean repeat;

	Bob next() {
		acc += rate;
		if (acc > 256) {
			acc -= 256;
			pos += 1;
			if (pos >= bobs.length) {
				if (repeat) {
					pos = 0;
				}
				else {
					pos = bobs.length-1;
				}
			}
		}
		return bobs[pos];
	}

	/**
	 * Construct an animation.
	 * 
	 * @param rate
	 *            Between 0x100 meaning "every frame" and 0 meaning "never".
	 * @param frames
	 *            The frames to animate.
	 * @param repeat
	 *            Repeat or stop at the end?
	 */
	Anim(int rate, Bob[] frames, boolean repeat) {
		this.rate = rate;
		this.bobs = frames;
		this.repeat = repeat;
	}
}
