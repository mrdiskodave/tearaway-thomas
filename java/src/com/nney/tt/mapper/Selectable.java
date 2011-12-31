package com.nney.tt.mapper;

import com.nney.tt.Bounded;
import com.nney.tt.geom.Coord;

public interface Selectable extends Bounded {
	void draw(MapperGC mgc, Coord where);
}
