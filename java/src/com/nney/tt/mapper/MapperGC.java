package com.nney.tt.mapper;

import com.nney.tt.geom.Coord;
import com.nney.tt.gfx.Font;
import com.nney.tt.gfx.GraphicsContext;

public class MapperGC {
	private GraphicsContext gc;
	private final Font debugFont;
	private final ColorCycler cycler;

	MapperGC(GraphicsContext gc, Font debugFont, ColorCycler cycler) {
		this.gc = gc;
		this.debugFont = debugFont;
		this.cycler = cycler;
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
		gc.fillRectangle(x + 1, y, w - 2, 1, c);
		gc.fillRectangle(x + 1, y + h - 1, w - 2, 1, c);

		gc.fillRectangle(x + w - 1, y, 1, h, c);
		gc.fillRectangle(x, y, 1, h, c);
	}

	public void drawTransBox(int x, int y, int w, int h, int c, int cf) {
		drawBox(x, y, w, h, c);
		x++;
		y++;
		w -= 2;
		h -= 2;
		gc.fillRectangle(x, y, w, h, cf);
	}

	public void drawSight(int x, int y, int i, int col) {
		int i2 = i*2+1;
		gc.fillRectangle(x - i, y, i2, 1, col);
		gc.fillRectangle(x, y - i, 1, i2, col);
	}

	public void drawSight2(int x, int y, int i, int col, int j, int col2) {
		int i2 = i*2+1;
		gc.fillRectangle(x - i, y, i2, 1, col);
		gc.fillRectangle(x, y - i, 1, i2, col);
		int j2 = j*2+1;
		drawTransBox(x-j, y-j, j2, j2, col, col2);
	}

	public void drawText(int x, int y, int fg, String text) {
		debugFont.draw(x, y, fg, 0, text);
	}

	public int charWidth() {
		return debugFont.charWidth();
	}

	public int charHeight() {
		return debugFont.charWidth();
	}

	public void drawText(int x, int y, int fg, int bg, String text) {
		gc.fillRectangle(x, y, 8 * text.length(), 8, bg);
		debugFont.draw(x, y, fg, 0, text);
	}
	
	public int process(int col) {
		return cycler.process(col);
	}
	
	public void nextFrame() {
		cycler.advance();
	}

	public Coord centreDisplacement() {
		return new Coord(screenWidth() / 2, screenHeight() / 2);
	}
}
