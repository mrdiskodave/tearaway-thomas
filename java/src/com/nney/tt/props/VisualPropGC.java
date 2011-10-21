package com.nney.tt.props;

import com.nney.tt.geom.Box;

public interface VisualPropGC {
	/**
	 * Draw a box (which you might position bats around the edge of).
	 * 
	 * @param box
	 *            A box in world coordinates (not screen coordinates).
	 * 
	 */
	void drawBox(Box box);
}
