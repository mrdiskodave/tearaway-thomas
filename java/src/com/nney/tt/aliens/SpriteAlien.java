package com.nney.tt.aliens;

import com.nney.tt.AlienServices;
import com.nney.tt.BitOp;
import com.nney.tt.sprites.Anim;
import com.nney.tt.sprites.Sprite;

public class SpriteAlien extends Alien {
	private static final int FLAG_BEHIND = 6;

	@Override
	public void load() {
		infront = BitOp.test(loadByte(OBflags), FLAG_BEHIND);
	}

	
	@Override
	public void update(AlienServices world) {
		changeAnimation(0);
		Sprite s = nextFrame();
		world.queueSprite(c, s);
	}

}
