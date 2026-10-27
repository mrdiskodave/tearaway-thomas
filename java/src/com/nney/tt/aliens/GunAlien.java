package com.nney.tt.aliens;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.props.PropAnn;
import com.nney.tt.sprites.Sprite;

/**
 * Futureland's laser guns (rgun_alien, lgun_alien, dgun_alien in s195). Guns
 * on walls slide up and down to line up with you; guns on ceilings slide
 * along. Every 50-113 frames they fire a {@link LaserAlien}. Touching a gun
 * stuns you.
 */
public class GunAlien extends AlienWithLocation {
	static final int FIRES_RIGHT = 89;
	static final int FIRES_LEFT = 90;
	static final int FIRES_DOWN = 91;

	@PropAnn(doc = "How far we can slide: up and down for wall guns, across for ceiling guns")
	public Box track;

	private int fireTimer;

	@Override
	public void resetTo(Coord p) {
		super.resetTo(p);
		track = Box.around(p, 50);
	}

	@Override
	public void loadFromLegacyData() {
		track = new Box((short) loadShort(OBleft), (short) loadShort(OBtop), (short) loadShort(OBright),
				(short) loadShort(OBbottom));
		fireTimer = loadByte(OBstatus0);
	}

	@Override
	public void update() {
		int type = alienInfo.typeCode;
		Coord p = srv.getPlayerPosition();
		if (type == FIRES_DOWN) {
			c.x = closerClip(c.x, p.x, track.left, track.right);
		}
		else {
			c.y = closerClip(c.y, p.y - 12, track.top, track.bottom);
		}

		if (--fireTimer < 0) {
			fireTimer = srv.randomness(64) + 50;
			fire(type);
		}

		Sprite s = firstFrame();
		srv.drawSprite(c, s);
		if (srv.collideAlienWithPlayerHiRes(c, s)) {
			srv.getThePlayer().stun();
		}
		freezeBounds = spriteBounds(s);
	}

	/** rld_gunfire: where the shot starts, which way it goes and how it looks. */
	private void fire(int type) {
		if (type == FIRES_RIGHT) srv.addAlien(new LaserAlien(c.copyAndAdd(20, 0), new Coord(6, 0), 0));
		else if (type == FIRES_LEFT) srv.addAlien(new LaserAlien(c.copyAndAdd(-20, 0), new Coord(-6, 0), 0));
		else srv.addAlien(new LaserAlien(c.copyAndAdd(0, 20), new Coord(0, 6), 1));
	}

	/** closerclip: one pixel towards the target, kept within min..max. */
	private static int closerClip(int cur, int dest, int min, int max) {
		dest = Math.max(min, Math.min(max, dest));
		return cur + Integer.signum(dest - cur);
	}
}
