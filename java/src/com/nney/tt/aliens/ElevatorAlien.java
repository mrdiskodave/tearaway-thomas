package com.nney.tt.aliens;

import com.nney.tt.Const;
import com.nney.tt.geom.Coord;
import com.nney.tt.input.Joystick;
import com.nney.tt.props.PropAnn;

/**
 * Futureland's elevator (flift_alien in s195): a lift the player drives. Stand
 * fully on it and push down or up and it sets off along its shaft at 8 pixels
 * a frame, stopping at the next floor.
 * 
 * The floors are marked in the map with special blocks (see fdef.txt): it stops
 * when it reaches a "liftstop" block, or a "liftstopright" three blocks to its
 * right. It won't go up if there's a "liftnoup" block five rows above, or
 * down with a "liftnodown" two rows below.
 */
public class ElevatorAlien extends LiftAlien {
	/** From the original's AGL table. */
	private static final int WIDTH = 44;
	private static final int SPEED = 8;

	/** Positions snap to rows where (y and 15) is 5 or 13 (flift_align). */
	private static final int[] ALIGN = { -3, 4, 3, 2, 1, 0, -1, -2, -3, 4, 3, 2, 1, 0, -1, -2 };

	@PropAnn(doc = "Where we start (top left)", label = "location")
	public Coord c = new Coord();

	/** 0 stopped, otherwise pixels per frame (+ is down). */
	private int velocity;

	@Override
	public void resetTo(Coord p) {
		c = p.copy();
	}

	@Override
	public void onLoaded() {
		depth = DEPTH_LIFTS;
		lifts = new LiftImpl[] { new LiftImpl(firstFrame(), WIDTH) };
	}

	@Override
	protected Coord[] currentPosition() {
		return new Coord[] { c.copyAndAdd(WIDTH / 2, 0) };
	}

	@Override
	public void move() {
		if (velocity != 0) travel();
		else maybeSetOff();
		super.move();
	}

	private void travel() {
		c.y += velocity;
		int row = c.y & Const.BLOCK_MASK;
		c.y += ALIGN[row];
		if (row == 5 && (blockAt(0, 0, "liftstop") || blockAt(3, 0, "liftstopright"))) {
			velocity = 0;
		}
	}

	private void maybeSetOff() {
		if (!srv.getThePlayer().isStandingOn(lifts[0])) return;
		// only if they're standing right on it
		int px = srv.getPlayerPosition().x - 8;
		if (px < c.x || px + 16 > c.x + WIDTH) return;

		int stick = srv.getJoystick();
		if ((stick & Joystick.DOWN) != 0) {
			if (!blockAt(1, 2, "liftnodown")) velocity = SPEED;
		}
		else if ((stick & Joystick.UP) != 0) {
			if (!blockAt(1, -5, "liftnoup")) velocity = -SPEED;
		}
	}

	/** Is the block so many blocks across and down from us a certain kind? */
	private boolean blockAt(int bx, int by, String kind) {
		return srv.blockInfoIs(c.copyAndAdd(bx * Const.BLOCK_SIZE, by * Const.BLOCK_SIZE), kind);
	}
}
