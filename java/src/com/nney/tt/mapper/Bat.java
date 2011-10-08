package com.nney.tt.mapper;

import com.nney.tt.geom.Coord;

public interface Bat {
	
	/**
	 * Where is it?
	 * @return It's location.
	 */
	Coord where();
	
	/**
	 * What happens when the user moves it.
	 * @param where It's new location.
	 */
	void onMove(Coord where);
}
