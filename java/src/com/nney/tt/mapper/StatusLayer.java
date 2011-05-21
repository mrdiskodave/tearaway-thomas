package com.nney.tt.mapper;

import java.util.HashSet;

import com.nney.tt.geom.Box;

public abstract class StatusLayer {
	private final MapperGC mgc;
	private HashSet<Integer> seenRow = new HashSet<Integer>();

	private int swc;
	protected int shc;
	protected int shp;
	private int swp;
	private int cwp;
	protected int chp;

	public StatusLayer(MapperGC mgc) {
		this.mgc = mgc;
		swp = mgc.screenWidth();
		shp = mgc.screenHeight();
		cwp = mgc.charWidth();
		chp = mgc.charHeight();
		swc = swp / cwp;
		shc = shp / chp;
	}

	protected abstract int computeFirstY();

	protected abstract int computeRow(int row);

	private int cx(int x) {
		if (x < 0) {
			x += swc;
		}
		x *= cwp;
		return x;
	}

	private int cy(int y) {
		y = computeRow(y);
		y *= chp;
		y += computeFirstY();
		return y;
	}

	public void draw(int x, int y, ButtonState status, String text) {
		int sx = cx(x);
		int sy = cy(y);
		if (!seenRow.contains(y)) {
			seenRow.add(y);
			mgc.fillRectangle(0, sy, swp, chp, 0x60000000);
		}
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
	
	public Box getBox(int x, int y, String text) {
		int sx = cx(x);
		int sy = cy(y);
		return Box.fromTopLeftAndSize(sx, sy, cwp * text.length(), chp);
	}

}
