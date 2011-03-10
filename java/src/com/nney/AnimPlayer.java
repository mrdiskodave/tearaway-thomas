package com.nney;

public class AnimPlayer {
	/**
	 * Where we are in the frame list.
	 */
	private int pos;

	/**
	 * Accumulator used to track how far rate progression towards next frame.
	 */
	private int acc;

	private final Anim anim;

	private int rate;

	private Runnable completionCallback;

	public AnimPlayer(Anim anim) {
		this.anim = anim;
		rate = anim.defaultRate;
	}
	
	public void setCompletionCallback(Runnable completionCallback) {
		this.completionCallback = completionCallback;
	}
	
	public Bob next() {
		acc += rate;
		if (acc > Anim.MAX_RATE) {
			acc -= Anim.MAX_RATE;
			pos += 1;
			if (pos >= anim.bobs.length) {
				if (anim.repeat) {
					pos = 0;
				}
				else {
					pos = anim.bobs.length-1;
				}
				if (completionCallback!=null) {
					completionCallback.run();
					completionCallback = null;
				}
			}
		}
		return anim.bobs[pos];
	}
	
	

}
