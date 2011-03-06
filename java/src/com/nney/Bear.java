package com.nney;

public class Bear {
	private Anim walkingLeft;

	void load(FrameHub frameHub) {
		walkingLeft = new Anim(128, frameHub.getFrames("wbear,n8"));
	}
}
