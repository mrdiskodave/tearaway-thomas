package com.nney.tt;

import com.nney.tt.geom.Coord;

/**
 * An abstraction of the player position. It has simple methods for moving one
 * pixel up, down, left and right. It only allows valid movement.
 * 
 * <p>
 * Bigger things based upon this will then also be guaranteed to be valid.
 */
public class PlayerPosition {
	private static final int MAX_SUCK_OR_CLIMB = 4;

	/**
	 * <p>
	 * There was a bug in the original where the player would get kicked up the
	 * screen by two pixels when moving from air to ground. This means jumps
	 * through ground (e.g. jumping through a tree-branch in order to land on
	 * it) would reach to 68 up pixels from the floor. A normal jump only
	 * reaches 66 pixels from the floor.
	 * 
	 * <p>
	 * I've decided <b>not</b> to include this bug but, instead, to give the
	 * player a JUMP_VELOCITY of -12.245f rather than -12. This means <b>all</b>
	 * jumps now reach 68 pixels. See {@link Player} for the details.
	 */
	private final static boolean CTC_BUG_FOR_BUG_EMULATION = false;

	private Coord c;
	private PlayerPositionServices srv;

	public PlayerPosition(Coord c, PlayerPositionServices srv) {
		this.c = c;
		this.srv = srv;
	}

	private boolean ig(int x, int y) {
		return srv.inTheGround(x, y);
	}

	public void move(int dx, int dy) {
		assert dx >= -1 && dx <= 1;
		assert dy >= -1 && dy <= 1;

		if (dy == -1) {
			c.y--;

			if (CTC_BUG_FOR_BUG_EMULATION) {
				if (ig(c.x, c.y) && !ig(c.x, c.y + 1)) {
					c.y -= 2;
				}
			}
		}
		if (dy == 1) {
			if (ig(c.x, c.y) || !ig(c.x, c.y + 1)) {
				c.y++;
			}
		}
		if (dx == 1 || dx == -1) {
			moveX(dx);
		}
	}

	private void moveX(int dx) {
		assert dx == 1 || dx == -1;

		// System.out.println("MoveX:"+dx);
		boolean now = ig(c.x, c.y);
		int ncx = c.x + dx;
		// TODO: useful for toyland??
		int tcx = ncx;

		if (now) {
			// now: ground
			int y = c.y;
			int patience = 5;
			for (;;) {
				y++;
				if (!ig(tcx, y)) {
					// yes! somewhere to fall onto
					xSuccess(ncx);
					break;
				}
				if (!ig(c.x, y) && --patience == 0) {
					// give up looking
					// (but not right away to allow for sloped undersides)
					break;
				}
			}
		}
		else {
			// now: air
			boolean after = ig(tcx, c.y + 0);
			if (after) {
				// air->ground: NO

				// except for a special case for standing:
				if (isStanding()) {
					for (int t = 1; t <= MAX_SUCK_OR_CLIMB; t++) {
						if (!ig(ncx, c.y - t)) {
							// climb!
							c.y -= t;
							xSuccess(ncx);
							break;
						}
					}
				}
			}
			else {
				// air->air: YES

				// a special case for standing:
				if (isStanding()) {
					// if we've walked off into space
					if (!ig(ncx, c.y + 1)) {
						for (int t = 1; t <= MAX_SUCK_OR_CLIMB; t++) {
							if (ig(ncx, c.y + t + 1)) {
								c.y += t;
								break;
							}
						}
					}
				}
				xSuccess(ncx);
			}
		}
	}

	private void xSuccess(int ncx) {
		c.x = ncx;
	}

	public Coord get() {
		return c.copy();
	}

	public boolean isStanding() {
		return !ig(c.x, c.y) && ig(c.x, c.y + 1);
	}

}
