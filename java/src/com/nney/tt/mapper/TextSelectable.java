package com.nney.tt.mapper;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;

public class TextSelectable implements Selectable {
	private final Box where;
	private final String text;

	TextSelectable(Box where, String text) {
		this.where = where;
		this.text = text;
	}

	@Override
	public Box getBounds() {
		return where;
	}

	@Override
	public void draw(MapperGC mgc, Coord where) {
		mgc.drawText(where.x + 2, where.y + 2, 0xffffffff, text);
	}
}
