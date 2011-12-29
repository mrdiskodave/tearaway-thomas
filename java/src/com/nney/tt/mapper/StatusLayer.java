package com.nney.tt.mapper;

import java.util.HashSet;

import com.nney.tt.geom.Box;

public abstract class StatusLayer {
	private final MapperGC mgc;
	private final HashSet<Integer> seenRow = new HashSet<Integer>();

	private final int screenWidthInCharacters;
	protected final int screenHeightInCharacters;
	protected final int screenHeightInPixels;
	private final int screenWidthInPixels;
	private final int characterWidthInPixels;
	protected final int characterHeightInPixels;

	public StatusLayer(MapperGC mgc) {
		this.mgc = mgc;
		screenWidthInPixels = mgc.screenWidth();
		screenHeightInPixels = mgc.screenHeight();
		characterWidthInPixels = mgc.charWidth();
		characterHeightInPixels = mgc.charHeight();
		screenWidthInCharacters = screenWidthInPixels / characterWidthInPixels;
		screenHeightInCharacters = screenHeightInPixels / characterHeightInPixels;
	}

	protected abstract int computeFirstY();

	protected abstract int computeRow(int row);

	private int cx(int x) {
		if (x < 0) {
			x += screenWidthInCharacters;
		}
		x *= characterWidthInPixels;
		return x;
	}

	private int cy(int y) {
		y = computeRow(y);
		y *= characterHeightInPixels;
		y += computeFirstY();
		return y;
	}

	public void draw(int x, int y, String text) {
		draw(x, y, ButtonState.PASSIVE, text);
	}

	public void drawWithCursor(int x, int y, int cursorX, String text) {
		// draw it as per normal
		draw(x, y, text);

		// draw the cursor block
		int sx = cx(x + cursorX);
		int sy = cy(y);
		mgc.fillRectangle(sx, sy, characterWidthInPixels, characterHeightInPixels, 0xffffffff);
		// reinstate anything we've overwritten
		if (cursorX < text.length()) {
			String s = text.substring(cursorX, cursorX + 1);
			mgc.drawText(sx, sy, 0xff000000, s);
		}
	}

	public void draw(int x, int y, ButtonState status, String text) {
		touch(y);
		int sx = cx(x);
		int sy = cy(y);
		switch (status) {
		case PASSIVE:
			mgc.drawText(sx, sy, 0xffffffff, text);
			break;
		case HOVER:
			mgc.drawText(sx, sy, 0xffffaaaa, 0x30ff0000, text);
			break;
		case PRESSED:
			mgc.drawText(sx, sy, 0xffbbffbb, 0x5000ff00, text);
			break;
		}
	}

	public void touch(int y) {
		itouch(y, 0x70000000);
	}

	public void highlightTouch(int y) {
		itouch(y, 0x90000000);
	}

	private void itouch(int y, int col) {
		if (!seenRow.contains(y)) {
			seenRow.add(y);
			int sy = cy(y);
			mgc.fillRectangle(0, sy, screenWidthInPixels, characterHeightInPixels, col);
		}
	}

	public Box getBox(int x, int y, int w, int h) {
		int sx = cx(x);
		int sy = cy(y);
		if (w < 0) w = screenWidthInCharacters;
		if (h < 0) h = screenHeightInCharacters;
		return Box.fromTopLeftAndSize(sx, sy, characterWidthInPixels * w, characterHeightInPixels * h);
	}

	public Box getBox(int x, int y, String text) {
		return getBox(x, y, text.length(), 1);
	}

	public int width() {
		return screenWidthInCharacters;
	}

}
