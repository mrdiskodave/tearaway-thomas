package com.nney.tt.aliens;

import com.nney.tt.props.PropAnn;
import com.nney.tt.sprites.Sprite;
import com.nney.utils.Math2;

public class SpriteAlien extends AlienWithLocation {
	private static final int FLAG_BEHIND = 6;

	@PropAnn(name = "Front", doc = "Do we appear in front of other graphics?")
	public boolean foreground;

	@Override
	public void loadFromLegacyData() {
		foreground = Math2.bitTest(loadByte(OBflags), FLAG_BEHIND);
	}

	@Override
	public void onPropUpdate() {
		super.onPropUpdate();
		depth = foreground ? DEPTH_FG_SCENARY : DEPTH_BG_SCENARY;
	}

	@Override
	public void update() {
		changeAnimation(0);
		Sprite s = nextFrame();
		srv.drawSprite(c, s);
		freezeBounds = spriteBounds(s);
	}
}
