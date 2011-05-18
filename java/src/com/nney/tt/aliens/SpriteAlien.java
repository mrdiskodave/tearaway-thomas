package com.nney.tt.aliens;

import com.nney.tt.BitOp;
import com.nney.tt.sprites.Sprite;

public class SpriteAlien extends Alien {
	private static final int FLAG_BEHIND = 6;
	
	@AlienProp(name = "Behind", doc = "Do we appear behind other graphics?")
	boolean behind;

	@Override
	public void loadFromLegacyData() {
		behind = !BitOp.test(loadByte(OBflags), FLAG_BEHIND);
		onPropUpdate();
	}
	
	@Override
	public void onPropUpdate() {
		depth = behind ? DEPTH_BACKGROUND : DEPTH_FOREGROUND;
	}
	
	@Override
	public void update() {
		changeAnimation(0);
		Sprite s = nextFrame();
		srv.drawSprite(c, s);
		freezeBounds = spriteBounds(s);
	}
}
