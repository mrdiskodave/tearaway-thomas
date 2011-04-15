package com.nney.tt.aliens;

import com.nney.tt.AlienServices;
import com.nney.tt.BitOp;
import com.nney.tt.sprites.Anim;
import com.nney.tt.sprites.Sprite;

public class SpriteAlien extends Alien {
	private static final int FLAG_BEHIND = 6;
	private boolean behind;

	@Override
	public void load() {
		behind = !BitOp.test(loadByte(OBflags), FLAG_BEHIND);
	}

	
	@Override
	public void update(AlienServices world) {
		changeAnimation(0);
		Sprite s = nextFrame();
		if (behind && world.collideAlienWithPlayerBounds(c, s)) {
			world.playerBehind();
		}
		world.queueSprite(c, s);
	}

}
