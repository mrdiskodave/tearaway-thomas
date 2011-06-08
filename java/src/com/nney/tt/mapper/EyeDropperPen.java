package com.nney.tt.mapper;

import com.nney.tt.geom.Coord;
import com.nney.tt.input.Keyboard;
import com.nney.tt.mapper.Mapper.CoordType;

public class EyeDropperPen extends Pen {
	@Override
	int key() {
		return Keyboard.KEY_I;
	}

	@Override
	void stroke(Coord c) {
		srv.setCurrentBlockFromMap(c);
	}
	
	@Override
	CoordType requiredCoordType() {
		return CoordType.WORLD_BLOCKS;
	}
}
