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
	private boolean standing;

	public PlayerPosition(Coord c, PlayerPositionServices srv) {
		this.c = c;
		this.srv = srv;
		this.feety = c.y;
		
		standing = !ig(c.x, c.y) && ig(c.x, c.y); 
	}

	private boolean ig(int x, int y) {
		return srv.inTheGround(x, y);
	}

	private void dropFeet() {
		feety = c.y;
		for (;;) {
			feety++;
			if (!ig(c.x, feety)) break;
		}
	}

	public void moveUp() {
		c.y--;
		standing = false;
	}

	public void moveDown() {
		boolean now = ig(c.x, c.y);
		boolean after = ig(c.x + 0, c.y + 1);
		if (now || !after) {
			c.y++;
		}
		else {
			standing = true;
		}
	}

	public void moveX(int dx) {
		boolean now = ig(c.x, c.y);
		boolean after = ig(c.x + dx, c.y + 0);
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
				
				// special case for standing:
				if (standing && !ig(ncx, c.y-1)) {
					c.y--;
					mx(ncx);
				}
			}
			else {
				// air->air
				if (!ig(ncx, c.y+1)) {
					standing = false;
				}
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
	
	public boolean isStanding() {
		return standing;
	}

}
