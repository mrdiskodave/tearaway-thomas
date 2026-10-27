package com.nney.tt.aliens;

import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Sprite;

/**
 * A shot from a {@link GunAlien} (lsr2_alien in s195): flies straight until it
 * hits something solid. Stuns you if it hits you.
 */
public class LaserAlien extends AlienWithLocation {
	private final Coord velocity;
	private final int look;

	public LaserAlien(Coord where, Coord velocity, int look) {
		this.c = where;
		this.velocity = velocity;
		this.look = look;
	}

	@Override
	public void update() {
		c.add(velocity);
		if (srv.inTheGround(c) || srv.keepInMap(c.copy())) {
			done();
			return;
		}
		Sprite s = anims.find(look).firstSprite();
		srv.drawSprite(c, s);
		if (srv.collideAlienWithPlayerHiRes(c, s)) {
			srv.getThePlayer().stun();
		}
	}
}
