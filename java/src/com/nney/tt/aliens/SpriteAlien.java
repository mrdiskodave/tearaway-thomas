package com.nney.tt.aliens;

import com.nney.tt.BitOp;
import com.nney.tt.geom.Box;
import com.nney.tt.sprites.Sprite;

public class SpriteAlien extends Alien {
	private static final int FLAG_BEHIND = 6;

	@Override
	public void load() {
		if (BitOp.test(loadByte(OBflags), FLAG_BEHIND)) {
			depth = DEPTH_FOREGROUND;
		}
	}

	
	@Override
	public void update() {
		changeAnimation(0);
		Sprite s = nextFrame();
		srv.drawSprite(c, s);
		freezeBounds = spriteBounds(s);
	}
}
