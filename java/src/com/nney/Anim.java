package com.nney;

public class Anim {
	static public final int MAX_RATE = 256;
	
	final public int defaultRate;

	/**
	 * The frames themselves.
	 */
	final public SpriteName[] bobs;

	/**
	 * Does it repeat?
	 */
	final public boolean repeat;

	/**
	 * Construct an animation.
	 * 
	 * @param defaultRate
	 *            Between {@link Anim#MAX_RATE} meaning "every frame" and 0 meaning "never".
	 * @param frames
	 *            The frames to animate.
	 * @param repeat
	 *            Repeat or stop at the end?
	 */
	Anim(int defaultRate, SpriteName[] frames, boolean repeat) {
		this.defaultRate = defaultRate;
		this.bobs = frames;
		this.repeat = repeat;
	}
}
