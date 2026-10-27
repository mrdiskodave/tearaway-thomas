package com.nney.tt.aliens;

import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Sprite;

/**
 * Futureland's electric field (elec_alien in s195). It flickers on and off,
 * staying each way for 16-47 frames. Walk into it while it's on and you're
 * thrown away from it.
 */
public class ElectricAlien extends AlienWithLocation {
	private int timer;
	private boolean off;

	@Override
	public void loadFromLegacyData() {
		timer = loadByte(OBstatus0);
		off = loadByte(OBstatus1) != 0;
	}

	@Override
	public void onLoaded() {
		changeAnimation(0);
	}

	@Override
	public void update() {
		if (--timer < 0) {
			timer = srv.randomness(32) + 16;
			off = !off;
		}
		if (off) {
			freezeBounds = spriteBounds(firstFrame());
			return;
		}
		Sprite s = nextFrame();
		srv.drawSprite(c, s);
		freezeBounds = spriteBounds(s);
		if (playerInOriginalBox(c, 153, 164, 166, 94)) {
			int away = c.x > srv.getPlayerPosition().x ? -1 : 1;
			srv.getThePlayer().blastAway(away, 0, 2);
		}
	}
}
