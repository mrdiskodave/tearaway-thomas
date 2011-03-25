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

	public AnimPlayer() {
	}

	public void changeAnimation(Anim freshAnim) {
		assert freshAnim != null;
		if (anim!=freshAnim) {
			anim = freshAnim;
			rate = freshAnim.defaultRate;
			pos = 0;
			acc = 0;
		}
		pause = false;
	}
	
	public boolean isNew() {
		return anim==null;
	}

	public void pause() {
		pause = true;
	}

	public void setCompletionCallback(Runnable completionCallback) {
		this.completionCallback = completionCallback;
	}

	public Sprite next() {
		assert anim != null;
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
						pos = anim.bobs.length - 1;
					}
					if (completionCallback != null) {
						completionCallback.run();
						completionCallback = null;
					}
				}
			}
		}
		return anim.bobs[pos];
	}
}
