package com.nney;

public class Bear {
	private Anim walkingLeft;
	private Anim facingForwards;
	private Anim walkingRight;
	Anim climbing;
	private Anim suprise;

	void load(FrameHub frameHub) {
		walkingLeft = new Anim(128, frameHub.getFrames("wbear,n8"));
		facingForwards = new Anim(0, frameHub.getFrames("n"));
		walkingRight = new Anim(128, frameHub.getFrames("n8"));
		climbing = new Anim(128, frameHub.getFrames("c6"));
		suprise = new Anim(0, frameHub.getFrames("n"));
	}
}
