package com.nney.tt.aliens;

import com.nney.tt.geom.Coord;
import com.nney.tt.props.PropAnn;
import com.nney.tt.sprites.Sprite;

/**
 * Iceland's balloon (blln_alien in s195). It bobs about on a spring around a
 * fixed point and every so often drops a bomb, which carries on with the
 * balloon's sideways motion. Touching it stuns you.
 * 
 * The spring is the original's integer arithmetic, kept exactly: positions
 * have 8 bits of fraction, velocities are signed bytes (which wrap), and each
 * frame the velocity changes by the distance from the anchor shifted right by
 * 4 (x) or 5 (y).
 */
public class BalloonAlien extends AlienWithLocation {
	@PropAnn(doc = "The point we bob around (OBleft, OBtop in the original)")
	public Coord anchor = new Coord();

	@PropAnn(doc = "Starting velocity, in the original's units (1/32 pixel per frame)")
	public Coord velocity = new Coord();

	private static final int WAITING = 0;
	private static final int READY = 1;
	private static final int DROPPED = 2;

	private int fracX;
	private int fracY;
	private int state;
	private int timer;

	@Override
	public void resetTo(Coord p) {
		super.resetTo(p);
		anchor = p.copy();
		velocity = new Coord(16, 0);
	}

	@Override
	public void loadFromLegacyData() {
		anchor = new Coord((short) loadShort(OBleft), (short) loadShort(OBtop));
		velocity = new Coord((byte) loadByte(OBstatus3), (byte) loadByte(OBstatus1));
		state = loadByte(OBstatus0) % 3;
		fracY = loadByte(OBstatus2);
		fracX = loadByte(OBstatus4);
		timer = loadByte(OBstatus6);
	}

	@Override
	public void onLoaded() {
		setAnimation(state);
	}

	@Override
	public void update() {
		int oldX = c.x;

		// MOVE X
		int vx = (byte) (velocity.x + springPull(anchor.x - c.x, 4));
		int x24 = (c.x << 8) + fracX + vx * 8;
		c.x = x24 >> 8;
		fracX = x24 & 0xff;
		velocity.x = vx;
		int xMove = (byte) (c.x - oldX);

		// MOVE Y
		int vy = (byte) (velocity.y + springPull(anchor.y - c.y, 5));
		int y24 = (c.y << 8) + fracY + vy * 8;
		c.y = y24 >> 8;
		fracY = y24 & 0xff;
		velocity.y = vy;

		// state machine: waiting, readying, drop, round again
		if (--timer < 0) {
			timer = srv.randomness(32) + 8;
			state = (state + 1) % 3;
			changeAnimation(state);
			if (state == DROPPED) {
				srv.addAlien(new BombAlien(c.copyAndAdd(6, 6), xMove));
			}
		}

		Sprite s = nextFrame();
		srv.drawSprite(c, s);
		if (srv.collideAlienWithPlayerHiRes(c, s)) {
			srv.getThePlayer().stun();
		}
	}

	/**
	 * The original's "lsr.w #n" of a 16 bit difference, of which only the low
	 * byte was used.
	 */
	private static int springPull(int diff, int shift) {
		return (byte) ((diff & 0xffff) >>> shift);
	}
}
