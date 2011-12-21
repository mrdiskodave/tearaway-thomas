package com.nney.tt.aliens;

import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Sprite;

public abstract class CollectableAlien extends AppearingAlien {
	@Override
	public void onLoaded() {
		super.onLoaded();
		depth = DEPTH_COLLECTABLES;
	}

	@Override
	protected void normalUpdate() {
		Sprite s = sameFrame();
		srv.drawSprite(c, s);
		handleCollison(c, s);

		if (!isFalling()) {
			freezeBounds = spriteBounds(s);
		}
	}

	protected void handleCollison(Coord c, Sprite s) {
		if (isCollisionDetected(c, s)) {
			giveBonus();
			done();
		}
	}

	protected boolean isCollisionDetected(Coord c, Sprite s) {
		return srv.collideAlienWithPlayerHiRes(c, s);
	}

	abstract protected void giveBonus();
}
