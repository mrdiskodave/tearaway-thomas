package com.nney;

import org.lwjgl.input.Keyboard;

public class Bear extends Alien {
	private static final Anim animWalkingLeft;
	private static final Anim animWalkingRight;
	private static final Anim animTurning;

	static {
		AnimBuilder ab = new AnimBuilder();
		ab.select("wbear");
		animWalkingLeft = ab.next(8).rate(100).repeat().build();
		animTurning = ab.next().build();
		animWalkingRight = ab.next(8).rate(100).repeat().build();
	}

	static void loadGraphics(FrameLoader frameLoader) {
		frameLoader.loadAll(animWalkingLeft, animWalkingRight, animTurning);
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
