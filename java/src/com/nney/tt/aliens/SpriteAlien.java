package com.nney.tt.aliens;

import com.nney.tt.BitOp;
import com.nney.tt.geom.Box;
import com.nney.tt.sprites.Anim;
import com.nney.tt.sprites.Sprite;

public class SpriteAlien extends Alien {
	private static final int FLAG_BEHIND = 6;

	@Override
	public void load() {
		infront = BitOp.test(loadByte(OBflags), FLAG_BEHIND);
	}

	
	@Override
	public void update() {
		changeAnimation(0);
		Sprite s = nextFrame();
		srv.queueSprite(c, s);
		freezeBounds = Box.fromTopLeftAndSize(c.x-s.handleX, c.y-s.handleY, s.w, s.h);
	}

}
