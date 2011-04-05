package com.nney.tt.sprites;

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

	private boolean pause;

	public AnimPlayer() {
	}

	public void changeAnimation(Anim freshAnim) {
		if (freshAnim==null) {
			anim = null;
		}
		else if (anim!=freshAnim) {
			anim = freshAnim;
			rate = freshAnim.defaultRate;
			pos = 0;
			acc = 0;
		}
		pause = false;
	}
	
	public void pause() {
		pause = true;
	}

	public Sprite next() {
		if (anim==null) return null;
		if (!pause) {
			acc += rate;
			if (acc > Anim.MAX_RATE) {
				acc -= Anim.MAX_RATE;
				pos += 1;
				if (pos >= anim.frames.length) {
					if (anim.repeatPos<0) {
						pos = anim.frames.length - 1;
					}
					else {
						pos = anim.repeatPos;
					}
				}
			}
		}
		return anim.frames[pos];
	}
}
