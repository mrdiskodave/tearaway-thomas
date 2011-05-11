package com.nney.tt.mapper;

import com.nney.tt.gfx.GraphicsContext;

public class MapperGC {
	private GraphicsContext gc;

	MapperGC(GraphicsContext gc) {
		this.gc = gc;
	}
	
	public void drawBox(int x, int y, int w, int h, int c) {
		gc.fillRectangle(x, y, w, 1, c);
		gc.fillRectangle(x, y, 1, h, c);
		gc.fillRectangle(x + w - 1, y, 1, h, c);
		gc.fillRectangle(x, y + h - 1, w, 1, c);
	}
	
	public void drawSight(int x, int y, int i, int col) {
		gc.fillRectangle(x - i, y, i * 2, 1, col);
		gc.fillRectangle(x, y - i, 1, i * 2, col);
	}
}
