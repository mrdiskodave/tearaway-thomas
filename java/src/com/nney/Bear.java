package com.nney;

public class Bear {
	private Anim walkingLeft;
	private Anim facingForwards;
	private Anim walkingRight;
	Anim climbing;
	private Anim suprise;

	void load(FrameFinder ff, FrameGetter fg) {
		ff.setFile("wbear");
		walkingLeft = new Anim(128, fg.get(ff.next(8)));
		facingForwards = new Anim(0, fg.get(ff.next()));
		walkingRight = new Anim(128, fg.get(ff.next(8)));
		climbing = new Anim(128, fg.get(ff.cycle(6)));
		suprise = new Anim(0, fg.get(ff.next()));
	}
}
