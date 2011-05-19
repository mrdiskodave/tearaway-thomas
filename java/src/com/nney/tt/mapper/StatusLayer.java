package com.nney.tt.mapper;

import java.util.HashSet;

import com.nney.tt.gfx.Bounds;

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
		swc = swp/cwp;
		shc = shp/chp;
	}

	protected abstract int computeFirstY();
	protected abstract int computeRow(int row);
	
	private int cx(int x) {
		if (x<0) {
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

	public void draw(int x, int y, int fg, String text) {
		if (!seenRow.contains(y)) {
			seenRow.add(y);
			mgc.fillRectangle(0, cy(y), swp, chp, 0x60000000);
		}
		mgc.drawText(cx(x), cy(y), fg, text);
	}
}
