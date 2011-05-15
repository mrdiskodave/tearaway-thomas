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
	
	public void drawTransBox(int x, int y, int w, int h, int c, int cf) {
		drawBox(x, y, w, h, c);
		x ++;
		y ++;
		w -= 2;
		h -= 2;
		gc.fillRectangle(x, y, w, h, cf);
	}
	
	public void drawSight(int x, int y, int i, int col) {
		drawTransBox(x-5, y-5, 11, 11, col);
		gc.fillRectangle(x - i, y, i * 2+1, 1, col);
		gc.fillRectangle(x, y - i, 1, i * 2+1, col);
	}

	private void drawTransBox(int i, int j, int k, int l, int col) {
		drawTransBox(i, j, k, l, col, col&0x080ffffff);
	}

	public void drawText(int x, int y, int col, String text) {
		debugFont.draw(x, y, col, 0, text);
	}
	
}
