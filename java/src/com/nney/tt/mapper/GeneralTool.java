package com.nney.tt.mapper;

import java.util.Map.Entry;

import com.nney.tt.Const;
import com.nney.tt.geom.Coord;

public class GeneralTool extends Tool {

	private final Pen[] pens;
	private final String name;
	private final Cursor cursor;

	GeneralTool(Mapper parent, Cursor cursor, String name, Pen... pens) {
		super(parent);
		for (Pen pen : pens) {
			pen.srv = parent;
		}
		this.cursor = cursor;
		this.name = name;
		this.pens = pens;
	}

	@Override
	void presentation() {
		for (Pen pen : pens) {
			pen.presentation();
		}
		if (cursor == Cursor.BLOCK) {
			drawBlockCursor();
		}
	}

	@Override
	void run() {
		checkPushTool();
		
		for (Pen pen : pens) {
			Coord m = srv.computeMousePos(pen.usesWorldCoords());
			if (pen.active) {
				boolean held = srv.isDown(pen.key());
				if (held) {
					pen.stroke(m.copy());
				}
				else {
					pen.up(m.copy());
					pen.active = false;
					lessBusy();
				}
			}
			else {
				boolean pressed = srv.justPressed() == pen.key();
				if (pressed) {
					boolean more = pen.down(m.copy());
					pen.active = true;
					moreBusy();
					if (!more) break;
				}
				else {
					pen.hover(m.copy());
				}
			}
		}
	}

	@Override
	String name() {
		return name;
	}
}
