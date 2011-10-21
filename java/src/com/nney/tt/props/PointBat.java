package com.nney.tt.props;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;

public abstract class PointBat implements Bat {
	@Override
	public Box box() {
		return Box.around(point(), 4);
	}
	
	abstract Coord point();
}
