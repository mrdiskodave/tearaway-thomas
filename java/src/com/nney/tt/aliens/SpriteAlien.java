package com.nney.tt.aliens;

import com.nney.tt.BitOp;
import com.nney.tt.sprites.Sprite;

@AlienInfoAnns({ @AlienInfoAnn(type = 18, gfx = "0cld0", name = "cloud0"), @AlienInfoAnn(type = 19, gfx = "0cld1", name = "cloud1"),
		@AlienInfoAnn(type = 20, gfx = "0cld2", name = "cloud2"), @AlienInfoAnn(type = 31, gfx = "gwall", name = "magicwall"), @AlienInfoAnn(type = 45, gfx = "gtrch", name = "torch"),
		@AlienInfoAnn(type = 42, gfx = "gpic2", name = "portrait5"), @AlienInfoAnn(type = 65, gfx = "wfce0", name = "face0"),
		@AlienInfoAnn(type = 66, gfx = "wfce1", name = "face1"), @AlienInfoAnn(type = 67, gfx = "wfce2", name = "face2"),
		@AlienInfoAnn(type = 68, gfx = "wflr0", name = "flower0"), @AlienInfoAnn(type = 69, gfx = "wflr1", name="flower1"),
		@AlienInfoAnn(type = 70, gfx = "wtrk0", name = "trunk0"), @AlienInfoAnn(type = 71, gfx = "wtrk1", name="trunk1"),
		@AlienInfoAnn(type = 93, gfx = "wfnsh", name="finish") })
public class SpriteAlien extends AlienWithLocation {
	private static final int FLAG_BEHIND = 6;

	@AlienProp(name = "Front", doc = "Do we appear in front of other graphics?", label = "foreground")
	public boolean foreground;

	@Override
	public void loadFromLegacyData() {
		foreground = BitOp.test(loadByte(OBflags), FLAG_BEHIND);
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
