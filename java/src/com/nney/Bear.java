package com.nney;

public class Bear {
	private Anim walkingLeft;
	private Anim facingForwards;
	private Anim walkingRight;
	Anim climbing;
	private Anim suprise;

	void loadGraphics(FrameSource fs) {
		fs.selectInput("wbear");
		walkingLeft = new Anim(128, fs.next(8));
		facingForwards = new Anim(0, fs.next());
		walkingRight = new Anim(128, fs.next(8));
		climbing = new Anim(128, fs.cycle(6));
		suprise = new Anim(0, fs.next());
	}
}
