package com.nney.tt;

import com.nney.tt.geom.Coord;

/**
 * An abstraction of the player position. It has simple methods for moving one
 * pixel up, down, left and right. It only allows valid movement.
 * <p>
 * Bigger things based on it will then also be guaranteed-valid.
 */
public class PlayerPosition {
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
		if (dy == -1) {
			c.y--;
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

		if (now) {
			// now: ground
			int y = c.y;
			int patience = 5;
			for (;;) {
				y++;
				if (!ig(ncx, y)) {
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
			boolean after = ig(c.x + dx, c.y + 0);
			if (after) {
				// air->ground: NO

				// except for a special case for standing:
				if (isStanding()) {
					if (!ig(ncx, c.y - 1)) {
						// climb!
						c.y--;
						xSuccess(ncx);
					}
					else if (!ig(ncx, c.y - 2)) {
						// climb more!
						c.y -= 2;
						xSuccess(ncx);
					}
				}
			}
			else {
				if (isStanding()) {
					if (!ig(ncx, c.y + 1)) {
						// no longer standing?
						if (ig(ncx, c.y + 2)) {
							// suck!
							c.y++;
						}
						else if (ig(ncx, c.y + 3)) {
							// suck more!
							c.y += 2;
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
