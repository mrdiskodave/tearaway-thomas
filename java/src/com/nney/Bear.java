package com.nney;

import org.lwjgl.input.Keyboard;

public class Bear extends Alien {

	public void move(World world) {
		world.fallOrRaise(c, 5);
		if (world.testKey(Keyboard.KEY_Q)) {
			c.x--;
			changeAnimation("left");
		}
		else if (world.testKey(Keyboard.KEY_W)) {
			c.x++;
			changeAnimation("right");
		}
		else {
			if (animPlayer.isNew()) {
				changeAnimation("turn");
			}
			animPlayer.pause();
		}
	}

}
