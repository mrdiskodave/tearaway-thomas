package com.nney.tt.mapper;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;

public interface BatTarget {
	/**
	 * Draw a bat. The bat is also remembered so the user can grab onto it with
	 * their mouse and move it around.
	 * 
	 * @param c
	 *            A location in world coordinates (not screen coordinates).
	 * 
	 * @see Prop#onBatMovement(int, Coord)
	 */
	void drawBat(Coord c);

	/**
	 * Draw a box (which you might position bats around the edge of).
	 * 
	 * @param box
	 *            A box in world coordinates (not screen coordinates).
	 * 
	 */
	void drawBox(Box box);
}
