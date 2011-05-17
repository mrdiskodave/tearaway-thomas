package com.nney.tt.mapper;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;

// control point render target!
public interface BatTarget {
	/**
	 * A position a bat.
	 * 
	 * @param c
	 *            A location in world coordinates (not screen coordinates). This
	 *            parameter will by this method so don't pass anything that
	 *            you'll need later.
	 */
	void drawBat(Coord c);
	void drawBox(Box box);
}
