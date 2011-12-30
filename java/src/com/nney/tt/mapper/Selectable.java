package com.nney.tt.mapper;

import com.nney.tt.Bounded;
import com.nney.tt.geom.Box;

public interface Selectable extends Bounded {
	void draw(MapperGC mgc, Box where);
}
