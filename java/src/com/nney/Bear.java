package com.nney;

import org.lwjgl.input.Keyboard;

public class Bear extends Alien {
	static private Anim animWalkingLeft;
	static private Anim animWalkingRight;
	private static Anim animTurning;

	static public void loadGraphics(AnimBuilder ab) {
		ab.select("wbear");
		animWalkingLeft = ab.next(8).rate(100).repeat().build();
		animTurning = ab.next().build();
		animWalkingRight = ab.next(8).rate(100).repeat().build();
//		animWalkingLeft = ab.otherWayTo(animWalkingRight).build();
//		animClimbing = ab.next(6).cycle().rate(80).repeat().build();
//		animSuprise = ab.next().build();
		
	}
	
	public void move(World world) {
		world.fallOrRaise(c, 5);
		if (world.testKey(Keyboard.KEY_Q)) {
			c.x--;
			animPlayer.changeAnimation(animWalkingLeft);
		}
		else if (world.testKey(Keyboard.KEY_W)) {
			c.x++;
			animPlayer.changeAnimation(animWalkingRight);
		}
		else {
			if (animPlayer.isNew()) {
				animPlayer.changeAnimation(animTurning);
			}
			animPlayer.pause();
		}
	}
}
