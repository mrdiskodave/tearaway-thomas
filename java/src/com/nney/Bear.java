package com.nney;

public class Bear extends Alien {
	private Anim animWalkingLeft;
	private Anim facingForwards;
	private Anim animWalkingRight;
	private Anim animClimbing;
	private Anim animSuprise;
	private Anim animTurning;

	void loadGraphics(AnimBuilder ab) {
		ab.select("wbear");
		animTurning = ab.next().build();
		animWalkingRight = ab.next(8).rate(100).repeat().build();
		animWalkingLeft = ab.otherWayTo(animWalkingRight).build();
		animClimbing = ab.next(6).cycle().rate(80).repeat().build();
		animSuprise = ab.next().build();
	}

	public void draw(World world) {
		animWalkingLeft.next().draw(c.x-world.screen.x, c.y-world.screen.y);
		world.fallOrRaise(c, 5);
		c.x--;
	}
}
