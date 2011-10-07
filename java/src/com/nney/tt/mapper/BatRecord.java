package com.nney.tt.mapper;

import com.nney.tt.geom.Coord;

public interface BatRecord extends Collidable {
	void setPosition(Coord c);
	Coord getPosition();
}
