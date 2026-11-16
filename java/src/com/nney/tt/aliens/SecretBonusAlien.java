package com.nney.tt.aliens;

import com.nney.tt.geom.Box;
import com.nney.tt.sprites.Sprite;

/**
 * A level's secret (icefruit_alien, patn_alien and gkey0_alien in s195).
 * Find it and the next bonus "fruit 'em up" stage is played; otherwise that
 * stage is skipped.
 * 
 * Iceland's and Toyland's are invisible; Ghostland's is a key you can see.
 * The worm ({@link WormAlien}) and the advice screens ({@link FuzzAlien}) are
 * secrets too.
 */
public class SecretBonusAlien extends AlienWithLocation {
	static final int TOY_PATTERN = 30;

	@Override
	public void update() {
		Sprite s = anims != null ? firstFrame() : null;
		if (s != null) srv.drawSprite(c, s);
		freezeBounds = s != null ? spriteBounds(s) : new Box(c.x - 16, c.y - 16, c.x + 16, c.y + 32);

		// the boxes are the original's (dc.w after easy_collideDP)
		boolean found = alienInfo.typeCode == TOY_PATTERN ? playerInOriginalBox(c, 160, 128, 165, 127)
				: playerInOriginalBox(c, 155, 131, 165, 125);
		if (found) {
			srv.secretBonusFound();
			srv.playSoundEffect("bigGem");
			done();
		}
	}

	@Override
	public void mapperUpdate() {
		if (anims != null) {
			super.mapperUpdate();
			return;
		}
		srv.drawDebugText(c, "secret bonus");
		freezeBounds = new Box(c.x - 16, c.y - 16, c.x + 16, c.y + 32);
	}
}
