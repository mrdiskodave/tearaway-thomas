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
	Bob[] frames;

	private final int resetTo;

	Bob next() {
		acc += rate;
		if (acc > 256) {
			acc -= 256;
			pos += 1;
			if (pos >= frames.length) {
				pos = resetTo;
				if (pos < 0) {
					pos += frames.length;
				}
			}
		}
		return frames[pos];
	}

	/**
	 * Construct an animation.
	 * 
	 * @param rate
	 *            Between 0x100 meaning "every frame" and 0 meaning "never".
	 * @param frames
	 *            The frames to animate.
	 * @param resetTo
	 *            Where to go when all the frames have played. Positive values
	 *            count forward from the start (0 is the first frame). Negative
	 *            values count backward from the end (-1 is the last frame).
	 */
	Anim(int rate, Bob[] frames, int resetTo) {
		this.rate = rate;
		this.frames = frames;
		this.resetTo = resetTo;
	}

	/**
	 * Construct an animation which loops (the default).
	 * 
	 * @param rate
	 * @param frames
	 */
	Anim(int rate, Bob[] frames) {
		this(rate, frames, 0);
	}
}
