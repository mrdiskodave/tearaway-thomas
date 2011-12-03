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

	private Coord c;
	private PlayerPositionServices srv;

	final private Coord last = new Coord();

	public Coord ceiling;

	public PlayerPosition(Coord c, PlayerPositionServices srv) {
		this.c = c;
		last.copyFieldsFrom(c);
		this.srv = srv;
		init();
	}

	private boolean ig(int x, int y) {
		return srv.inTheGround(x, y);
	}

	public void move(int dx, int dy) {
		if (!c.equals(last)) {
			init();
		}

		assert dx >= -1 && dx <= 1;
		assert dy >= -1 && dy <= 1;

		if (dy == -1) {
			c.y--;
			if (ig(c.x, c.y)) {
				if (!ig(c.x, c.y + 1)) {
					// speedwise it is a shame that we've already moved it
					ceiling = c.copyAndAdd(0, 1);
				}
			}
			else {
				ceiling = null;
			}
		}
		if (dy == 1) {
			if (ig(c.x, c.y + 1)) {
				if (ig(c.x, c.y)) {
					c.y++;
				}
			}
			else {
				ceiling = null;
				c.y++;
			}
		}
		if (dx == 1 || dx == -1) {
			moveX(dx);
		}

		if (ig(c.x, c.y)) {
			assert ceiling != null;
		}
		else {
			assert ceiling == null;
		}

		last.copyFieldsFrom(c);
	}

	public void init() {
		ceiling = null;
		if (ig(c.x, c.y)) {
			System.out.println("re-finding ceiling");
			ceiling = c.copy();
			do {
				ceiling.y++;
			} while (ig(ceiling.x, ceiling.y));
		}
	}

	private void moveX(int dx) {
		assert dx == 1 || dx == -1;

		// System.out.println("MoveX:"+dx);
		boolean now = ig(c.x, c.y);
		int ncx = c.x + dx;

		if (now) {
			// now: ground
			assert ceiling != null;

			boolean cg = ig(ncx, ceiling.y);
			if (cg) {
				// ceiling is in the ground
				// it needs to go down a bit
				// (because the ceiling may be sloped)
				// OR
				// we cannot go there
				for (int t = 1; t <= MAX_SUCK_OR_CLIMB; t++) {
					if (!ig(ncx, ceiling.y + t)) {
						xSuccess(ncx);
						ceiling.x = ncx;
						ceiling.y += t;
						break;
					}
				}
			}
			else {
				// ceiling is in the air
				// take it up til to the ceiling
				while (!ig(ncx, ceiling.y - 1)) {
					ceiling.y--;
				}
				ceiling.x = ncx;
				xSuccess(ncx);
			}

			if (!ig(c.x, c.y)) {
				ceiling = null;
			}

			// int y = c.y;
			// int patience = 5;
			// for (;;) {
			// y++;
			// if (!ig(ncx, y)) {
			// // System.out.println("Success at " + new Coord(tcx, y));
			// // air below us in the new location.
			// // yes! somewhere to fall onto.
			// xSuccess(ncx);
			// break;
			// }
			// if (!ig(c.x, y) && --patience == 0) {
			// // System.out.println("Gave up at " + new Coord(c.x, y));
			// // air below us in the old location
			// // give up looking
			// // (but not right away to allow for sloped undersides)
			// break;
			// }
			//
			// // so:
			// // effectively when we are in the ground we track the ceiling
			// // below us to make sure we don't go past an upper corner
			//
			// }
		}
		else {
			assert ceiling == null;

			// now: air
			boolean after = ig(ncx, c.y);
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
