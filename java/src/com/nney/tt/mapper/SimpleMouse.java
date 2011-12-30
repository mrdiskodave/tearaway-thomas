package com.nney.tt.mapper;

import com.nney.tt.geom.Coord;
import com.nney.tt.input.Pointer;

public class SimpleMouse {
	private final Pointer target;

	SimpleMouse(Pointer target) {
		this.target = target;
	}

	Coord get() {
		return new Coord(target.getX(), target.getY());
	}

	Coord set(Coord c) {
		Coord answer = get();
		target.set(c.x, c.y);
		return answer;
	}
}
