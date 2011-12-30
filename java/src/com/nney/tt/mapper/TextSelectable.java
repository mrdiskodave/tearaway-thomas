package com.nney.tt.mapper;

import com.nney.tt.geom.Box;

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
	public void draw(MapperGC mgc, Box where) {
		mgc.drawText(where.left + 2, where.top + 2, 0xffffffff, text);
	}
}
