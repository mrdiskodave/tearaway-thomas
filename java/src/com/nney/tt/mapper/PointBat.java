package com.nney.tt.mapper;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;

public abstract class PointBat implements Bat {
	@Override
	public Box where2() {
		return Box.around(where(), 4);
	}
	
	abstract Coord where();
}
