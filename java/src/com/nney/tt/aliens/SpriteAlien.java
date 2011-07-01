package com.nney.tt.aliens;

import com.nney.tt.BitOp;
import com.nney.tt.sprites.Sprite;

@AlienInfoAnns({ @AlienInfoAnn(type = 18, gfx = "0cld0"), @AlienInfoAnn(type = 19, gfx = "0cld1"),
		@AlienInfoAnn(type = 20, gfx = "0cld2"), @AlienInfoAnn(type = 31, gfx = "gwall"), @AlienInfoAnn(type = 45, gfx = "gtrch"),
		@AlienInfoAnn(type = 42, gfx = "gpic2"), @AlienInfoAnn(type = 65, gfx = "wfce0"),
		@AlienInfoAnn(type = 66, gfx = "wfce1"), @AlienInfoAnn(type = 67, gfx = "wfce2"),
		@AlienInfoAnn(type = 68, gfx = "wflr0"), @AlienInfoAnn(type = 69, gfx = "wflr1"),
		@AlienInfoAnn(type = 70, gfx = "wtrk0"), @AlienInfoAnn(type = 71, gfx = "wtrk1"),
		@AlienInfoAnn(type = 93, gfx = "wfnsh") })
public class SpriteAlien extends AlienWithLocation {
	private static final int FLAG_BEHIND = 6;

	@AlienProp(name = "Front", doc = "Do we appear in front of other graphics?", label = "foreground")
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
