package com.nney.tt.mapper;

import com.nney.tt.geom.Coord;

public interface Collidable {
	boolean inside(Coord c);
}
