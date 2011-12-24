package com.nney.tt.aliens;

import com.nney.tt.geom.Coord;

public interface Lift {
	Coord lastFrameDelta();

	boolean horizontalOverlap(int x);

	boolean isScoopingUp(Coord lc, Coord cr);
}