package com.nney.tt.sprites;

import com.nney.utils.Math2;

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

	private boolean animEnded;

	private int rateScale = 100;

	public AnimPlayer() {
	}

	public void setRateScale(int rs) {
		rateScale = rs;
	}

	public void changeAnimation(Anim freshAnim) {
		assert freshAnim != null;

		if (anim != freshAnim) {
			setAnimation(freshAnim);
		}
	}

	public void setAnimation(Anim freshAnim) {
		// System.out.println("Fresh len "+freshAnim.frames.length);
		anim = freshAnim;
		setRate(freshAnim.defaultRate);
		rewind();
	}

	public void customiseRate(int customRate) {
		setRate(customRate);
	}

	private void setRate(int r) {
		rate = Math2.percent(r, rateScale);

	}

	public void rewind() {
		pos = 0;
		acc = 0;
		animEnded = false;
	}

	public Sprite nextFrame() {
		Sprite answer = currentFrame();
		advance();
		return answer;
	}

	public Sprite currentFrame() {
		return anim.sprites[pos];
	}

	private void advance() {
		assert anim != null;
		acc += rate;
		if (acc > Anim.MAX_RATE) {
			acc -= Anim.MAX_RATE;
			pos += 1;
			if (pos >= anim.sprites.length) {
				if (anim.repeatPos < 0) {
					animEnded = true;
					pos = anim.sprites.length - 1;
				}
				else {
					pos = anim.repeatPos;
				}
			}
		}
	}

	public boolean hasAnimEnded() {
		return animEnded;
	}
}
