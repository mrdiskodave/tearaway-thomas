package com.nney.tt.aliens;

import com.nney.tt.geom.Box;

/**
 * An invisible trigger hidden somewhere in a level (icefruit_alien in s195,
 * and its cousins). Find it and the next bonus "fruit 'em up" stage is
 * played; otherwise that stage is skipped.
 */
public class SecretBonusAlien extends AlienWithLocation {
	@Override
	public void update() {
		// dc.w 155,131,165,125 in the original: 10 wide, 6 high
		Box b = new Box(c.x - 5, c.y - 3, c.x + 5, c.y + 3);
		freezeBounds = b;
		if (srv.collideBoxWithPlayer(b)) {
			srv.secretBonusFound();
			srv.playSoundEffect("gem");
			done();
		}
	}

	@Override
	public void mapperUpdate() {
		srv.drawDebugText(c, "secret bonus");
		freezeBounds = new Box(c.x - 5, c.y - 3, c.x + 5, c.y + 3);
	}
}
