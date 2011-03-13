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

	private Anim anim;

	private int rate;

	private Runnable completionCallback;

	private boolean pause;

	public AnimPlayer(Anim anim) {
		changeAnimation(anim);
	}
	
	public void changeAnimation(Anim anim2) {
		if (anim2!=anim) {
			anim = anim2;
			rate = anim.defaultRate;
			pos = 0;
			acc = 0;
		}
		pause = false;
	}
	
	public void pause() {
		pause = true;
	}

	public void setCompletionCallback(Runnable completionCallback) {
		this.completionCallback = completionCallback;
	}
	
	public Bob next() {
		if (!pause) {
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
		}
		return anim.bobs[pos];
	}
}
