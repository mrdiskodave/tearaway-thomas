package com.nney.tt;

import com.nney.tt.geom.Coord;

/**
 * An abstraction of the player position. It will have simple methods for moving
 * one pixel up, down, left and right. It will only allow valid movement. Bigger
 * things based on it will then also be guarenteed-valid.
 */
public class PlayerPosition {
	private Coord c;
	private PlayerPositionServices srv;
	private int feety;

	public PlayerPosition(Coord c, PlayerPositionServices srv) {
		this.c = c;
		this.srv = srv;
		this.feety = c.y;
		dropFeet();
	}

	private boolean pig() {
		return ig(c);
	}

	private boolean pig(int x, int y) {
		return ig(c, x, y);
	}

	private boolean ig(int x, int y) {
		return srv.inTheGround(x, y);
	}

	private boolean ig(Coord c) {
		return ig(c.x, c.y);
	}

	private boolean ig(Coord c, int dx, int dy) {
		return ig(c.x + dx, c.y + dy);
	}

	private void dropFeet() {
		feety = c.y;
		for (;;) {
			feety++;
			if (!ig(c.x, feety)) break;
		}
//		int f = feety;
//		while (ig(c.x, feety) || !ig(c.x, feety + 1)) {
//			feety++;
//		}
//		System.out.println("Feet drop:"+(feety-f));
	}

	public void moveUp() {
		boolean now = pig();
		boolean after = pig(0, -1);
		c.y--;
		if (now && !after) {
//			feety = c.y;
		}
	}

	public void moveDown() {
		boolean now = pig();
		boolean after = pig(0, 1);
		if (now || !after) {
			c.y++;
		}
		else {
//			feety = c.y;
		}
	}

	public void moveX(int dx) {
		boolean now = pig();
		boolean after = pig(dx, 0);
		int ncx = c.x + dx;

		if (now) {
			// now: ground
			dropFeet();
			for (int s = c.y+1; s<=feety; s++) {
				if (!ig(ncx, s)) {
					mx(ncx);
					break;
				}
			}
		}
		else {
			// now: air
			if (after) {
				// air->ground: NO
			}
			else {
				mx(ncx);
			}
		}
	}

	public void mx(int ncx) {
		c.x = ncx;
	}

	public Coord get() {
		return c.copy();
	}

	public Coord getFeet() {
		return new Coord(c.x, feety);
	}

}
