package com.nney.tt.aliens;

import com.nney.tt.Pipes;
import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Sprite;

/**
 * The open end of one of Futureland's pipes (bend_alien, lend_alien and
 * rend_alien in s195). Get close and in you go; the {@link com.nney.tt.Player}
 * does the travelling.
 * 
 * Which end it is comes from the type: a bottom end you jump up into, or a
 * left or right end you walk into.
 */
public class PipeEndAlien extends AlienWithLocation {
	/** Type codes from the original. */
	static final int RIGHT_END = 51;
	static final int BOTTOM_END = 52;
	static final int LEFT_END = 53;

	@Override
	public void update() {
		Sprite s = firstFrame();
		srv.drawSprite(c, s);

		int type = alienInfo.typeCode;
		Coord p = srv.getPlayerPosition();
		int dx = p.x - c.x;
		int dy = p.y - c.y; // to the player's feet

		// the boxes and mouths are from easy_collideDP and pipeIDM
		if (type == BOTTOM_END) {
			if (dx >= -23 && dx <= 24 && dy >= 32 && dy <= 93) {
				srv.getThePlayer().requestPipe(Pipes.NORTH, c.copyAndAdd(0, 23));
			}
		}
		else if (type == LEFT_END) {
			if (dx >= -71 && dx <= -24 && dy >= -16 && dy <= 45) {
				srv.getThePlayer().requestPipe(Pipes.EAST, c.copyAndAdd(-23, 11));
			}
		}
		else if (type == RIGHT_END) {
			if (dx >= 24 && dx <= 71 && dy >= -16 && dy <= 45) {
				srv.getThePlayer().requestPipe(Pipes.WEST, c.copyAndAdd(23, 11));
			}
		}
		freezeBounds = spriteBounds(s);
	}
}
