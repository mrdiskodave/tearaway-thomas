package com.nney.tt;

import com.nney.tt.geom.Coord;

/**
 * An abstraction of the player position. It will have simple methods for moving
 * one pixel up, down, left and right. It will only allow valid movement. Bigger
 * things based on it will then also be guaranteed-valid.
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

	public void moveUp() {
//		System.out.println("MoveUp");
		c.y--;
	}

	public void moveDown() {
		boolean now = ig(c.x, c.y);
		boolean after = ig(c.x + 0, c.y + 1);
		if (now || !after) {
			c.y++;
		}
	}

	public void moveX(int dx) {
		assert dx==1 || dx==-1;
		
//		System.out.println("MoveX:"+dx);
		boolean now = ig(c.x, c.y);
		boolean after = ig(c.x + dx, c.y + 0);
		int ncx = c.x + dx;

		if (now) {
			// now: ground
			int s = c.y;
			int patience = 5; 
			for (;;) {
				s++;
				if (!ig(ncx, s)) {
					// yes! somewhere to fall onto
					mx(ncx);
					break;
				}
				if (!ig(c.x, s) && --patience==0) {
					// give up looking
					break;
				}
			}
		}
		else {
			// now: air
			if (after) {
				// air->ground: NO
				
				// except for a special case for standing:
				if (isStanding() && !ig(ncx, c.y-1)) {
					// climb!
					c.y--;
					mx(ncx);
				}
			}
			else {
				// air->air: YES
				if (isStanding()) {
					if (!ig(ncx, c.y+1)) {
						if (ig(ncx, c.y+2)) {
							// suck!
							c.y++;
						}
					}
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

	public boolean isStanding() {
		return !ig(c.x, c.y) && ig(c.x, c.y+1); 
	}

}
