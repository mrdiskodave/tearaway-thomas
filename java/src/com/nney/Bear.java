package com.nney;

import org.lwjgl.input.Keyboard;

public class Bear extends Alien {
	private static final Anim ANIM_WALKING_LEFT;
	private static final Anim ANIM_WALKING_RIGHT;
	private static final Anim ANIM_TURNING;

	static {
		AnimBuilder ab = new AnimBuilder();
		ab.select("wbear");
		ANIM_WALKING_LEFT = ab.next(8).rate(100).repeat().build();
		ANIM_TURNING = ab.next().build();
		ANIM_WALKING_RIGHT = ab.next(8).rate(100).repeat().build();
	}

	static void loadGraphics(FrameLoader frameLoader) {
		frameLoader.loadAll(ANIM_WALKING_LEFT, ANIM_WALKING_RIGHT, ANIM_TURNING);
	}
	
	

	public void move(World world) {
		world.fallOrRaise(c, 5);
		if (world.testKey(Keyboard.KEY_Q)) {
			c.x--;
			animPlayer.changeAnimation(ANIM_WALKING_LEFT);
		}
			else if (world.testKey(Keyboard.KEY_W)) {
				c.x++;
			animPlayer.changeAnimation(ANIM_WALKING_RIGHT);
		}
		else {
			if (animPlayer.isNew()) {
				animPlayer.changeAnimation(ANIM_TURNING);
			}
			animPlayer.pause();
		}
	}

}
