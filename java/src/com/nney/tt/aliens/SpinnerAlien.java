package com.nney.tt.aliens;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.props.PropAnn;
import com.nney.tt.sprites.Sprite;

/**
 * Futureland's spinning thing (spin_alien in s195): ricochets around a box at
 * 2 pixels a frame each way, bouncing off the box's edges and off anything
 * solid. Touching it stuns you.
 */
public class SpinnerAlien extends AlienWithLocation {
	private static final int SPEED = 2;
	private static final int REACH = 10;
	private static final int HALF_WIDTH = 5;

	@PropAnn(doc = "The box we bounce around in")
	public Box box;

	@PropAnn(doc = "Heading right? (otherwise left)")
	public boolean right;

	@PropAnn(doc = "Heading down? (otherwise up)")
	public boolean down;

	@Override
	public void resetTo(Coord p) {
		super.resetTo(p);
		box = Box.around(p, 60);
	}

	@Override
	public void loadFromLegacyData() {
		box = new Box((short) loadShort(OBleft), (short) loadShort(OBtop), (short) loadShort(OBright),
				(short) loadShort(OBbottom));
		right = loadByte(OBstatus0) != 0;
		down = loadByte(OBstatus1) != 0;
	}

	@Override
	public void onLoaded() {
		changeAnimation(0);
	}

	@Override
	public void update() {
		// across: look ahead 10, above and below our middle
		int nx = c.x + (right ? SPEED : -SPEED);
		int edge = c.x + (right ? REACH : -REACH);
		boolean bounceX = right ? edge >= box.right : edge <= box.left;
		if (!bounceX) {
			bounceX = srv.inTheGround(edge, c.y - HALF_WIDTH) || srv.inTheGround(edge, c.y + HALF_WIDTH);
		}
		if (bounceX) {
			nx = c.x;
			right = !right;
		}

		// up and down: the same, from where we've just moved to
		int ny = c.y + (down ? SPEED : -SPEED);
		edge = c.y + (down ? REACH : -REACH);
		boolean bounceY = down ? edge >= box.bottom : edge <= box.top;
		if (!bounceY) {
			bounceY = srv.inTheGround(nx - HALF_WIDTH, edge) || srv.inTheGround(nx + HALF_WIDTH, edge);
		}
		if (bounceY) {
			ny = c.y;
			down = !down;
		}
		c.x = nx;
		c.y = ny;

		Sprite s = nextFrame();
		srv.drawSprite(c, s);
		if (srv.collideAlienWithPlayerHiRes(c, s)) {
			srv.getThePlayer().stun();
		}
	}
}
