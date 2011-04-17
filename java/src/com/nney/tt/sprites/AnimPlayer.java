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
	}
	
	public Sprite next() {
		//if (anim==null) return null;
		advance();
		return current();
	}

	public Sprite current() {
		return anim.frames[pos];
	}

	private void advance() {
		assert anim!=null;
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
}
