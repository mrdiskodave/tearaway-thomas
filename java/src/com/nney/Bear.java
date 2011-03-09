package com.nney;

public class Bear {
	private Anim walkingLeft;
	private Anim facingForwards;
	Anim walkingRight;
	Anim climbing;
	private Anim suprise;
	public Coord c = new Coord();

	void loadGraphics(FrameSource fs) {
		fs.selectInput("wbear");
		walkingLeft = new Anim(80, fs.next(8));
		facingForwards = new Anim(0, fs.next());
		walkingRight = new Anim(80, fs.next(8));
		climbing = new Anim(128, fs.cycle(6));
		suprise = new Anim(0, fs.next());
	}

	public void draw(World world) {
		walkingRight.next().draw(c.x-world.screen.x, c.y-world.screen.y);

		world.fallOrRaise(c, 5);
		c.x++;
	}
}
