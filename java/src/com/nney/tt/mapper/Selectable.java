package com.nney.tt.mapper;

import com.nney.tt.geom.Box;

public interface Selectable {
	Box where();

	void draw(MapperGC mgc, Box where);
}
