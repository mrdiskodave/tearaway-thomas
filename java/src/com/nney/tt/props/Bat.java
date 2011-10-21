package com.nney.tt.props;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;

public interface Bat {
	
	/**
	 * Where is it?
	 * @return It's location.
	 */
	Box box();
	
	/**
	 * The user has moved the returned {@link Box} so respond to that.
	 * @param where Where is the centre of the {@link Box} now?
	 */
	void onMove(Coord where);
}
