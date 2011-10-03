package com.nney.tt.mapper;

import com.nney.tt.geom.Coord;

public abstract class Bat {
	abstract Coord where();
	abstract void onMove(Coord where);
}
