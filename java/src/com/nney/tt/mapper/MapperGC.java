package com.nney.tt.mapper;

import com.nney.tt.gfx.Font;
import com.nney.tt.gfx.GraphicsContext;

public class MapperGC {
	private GraphicsContext gc;
	private final Font debugFont;

	MapperGC(GraphicsContext gc, Font debugFont) {
		this.gc = gc;
		this.debugFont = debugFont;
	}

	public void fillRectangle(int x, int y, int w, int h, int col) {
		gc.fillRectangle(x, y, w, h, col);
	}

	public int screenWidth() {
		return gc.screenWidth();
	}

	public int screenHeight() {
		return gc.screenHeight();
	}
	
	public void drawBox(int x, int y, int w, int h, int c) {
		gc.fillRectangle(x+1, y, w-2, 1, c);
		gc.fillRectangle(x+1, y + h - 1, w-2, 1, c);

		gc.fillRectangle(x + w - 1, y, 1, h, c);
		gc.fillRectangle(x, y, 1, h, c);
	}
	
	public void drawSight(int x, int y, int i, int col) {
		gc.fillRectangle(x - i, y, i * 2, 1, col);
		gc.fillRectangle(x, y - i, 1, i * 2, col);
	}

	public void drawText(int x, int y, int col, String text) {
		debugFont.draw(x, y, col, 0, text);
	}
}
