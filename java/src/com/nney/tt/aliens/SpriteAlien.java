package com.nney.tt.aliens;

import com.nney.tt.BitOp;
import com.nney.tt.sprites.Sprite;

public class SpriteAlien extends AlienWithLocation {
	private static final int FLAG_BEHIND = 6;

	@AlienProp(name = "Front", doc = "Do we appear in front of other graphics?")
	public boolean foreground;

	@Override
	public void loadFromLegacyData() {
		foreground = BitOp.test(loadByte(OBflags), FLAG_BEHIND);
		onPropUpdate();
	}

	@Override
	public void onPropUpdate() {
		depth = foreground ? DEPTH_FOREGROUND : DEPTH_BACKGROUND;
	}

	@Override
	public void update() {
		changeAnimation(0);
		Sprite s = nextFrame();
		srv.drawSprite(c, s);
		freezeBounds = spriteBounds(s);
	}
}
