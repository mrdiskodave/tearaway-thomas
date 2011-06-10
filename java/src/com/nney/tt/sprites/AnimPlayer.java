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

	private boolean animEnded;

	public AnimPlayer() {
	}

	public void changeAnimation(Anim freshAnim) {
		assert freshAnim!=null;
		
		if (freshAnim == null) {
			anim = null;
		}
		else if (anim != freshAnim) {
			// System.out.println("Fresh len "+freshAnim.frames.length);
			anim = freshAnim;
			rate = freshAnim.defaultRate;
			rewind();
		}
	}
	
	public void customiseRate(int customRate) {
		rate = customRate;
	}

	public void rewind() {
		pos = 0;
		acc = 0;
		animEnded = false;
	}

	public Sprite next() {
		Sprite answer = current();
		advance();
		return answer;
	}

	public Sprite current() {
		return anim.frames[pos];
	}

	private void advance() {
		assert anim != null;
		acc += rate;
		if (acc > Anim.MAX_RATE) {
			acc -= Anim.MAX_RATE;
			pos += 1;
			if (pos >= anim.frames.length) {
				if (anim.repeatPos < 0) {
					pos = anim.frames.length - 1;
				}
				else {
					pos = anim.repeatPos;
				}
				animEnded = true;
			}
		}
	}

	public boolean hasAnimEnded() {
		return animEnded;
	}
}
