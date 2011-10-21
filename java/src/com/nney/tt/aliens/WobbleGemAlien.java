package com.nney.tt.aliens;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Sprite;
import com.nney.utils.Math2;

@AlienInfoAnns({ @AlienInfoAnn(type = 2, gfx = "0ygem", score=50, name="yellowGem"),
	@AlienInfoAnn(type = 3, gfx = "0pgem", score=100, name="purpleGem")
})
public class WobbleGemAlien extends GemAlien {
	private static final int FLAG_NO_WOBBLE = 3;

	private static final int[] WOBBLE = { 0, -1, -2, -3, -2, -1, 0, 1, 2, 3, 2, 1 };

	@PropAnn(name = "Wobble", doc = "Do we wobble?", label = "wobble")
	public boolean wobble = true;

	private int wobblePhase;

	@Override
	public void loadFromLegacyData() {
		super.loadFromLegacyData();
		wobble = !Math2.bitTest(loadByte(OBflags), FLAG_NO_WOBBLE);
	}

	@Override
	public void onLoaded() {
		super.onLoaded();
		wobblePhase = c.pseudorandom(WOBBLE.length, 100);
	}

	@Override
	protected void normalUpdate() {
		Coord c2 = c.copy();
		if (wobble && !isFalling()) {
			c2.y += WOBBLE[wobblePhase++];
			wobblePhase %= WOBBLE.length;
		}
		Sprite s = nextFrame();
		srv.drawSprite(c2, s);

		handleCollison(c2, s);
		// TODO: override 
		// collisionDetection(c2, s)
		// because we're too small
		// (so player tunnels when sliding on ice)

		if (!isFalling()) {
			freezeBounds = Box.around(c, 20, 20);
		}
	}
}
