package com.nney.tt.mapper;

import java.util.List;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;

public class SelectionScreen {
	/**
	 * The colour we use to highlight the current block.
	 */
	private static final int COL_CURRENT_BLOCK = 0xffff0000;

	/**
	 * Our background colour.
	 */
	private static final int COL_BACKGROUND = 0xff0020ff;

	private final List<Selectable> content;
	private final ScrollingWithMargin swm;
	private final MapperGC mgc;

	private int hover;

	private final MapperMousePosition mmp;

	private Coord savePosition;

	private Coord ourPosition = new Coord(0, 0);

	SelectionScreen(MapperGC mgc, MapperMousePosition mmp, List<Selectable> content) {
		this.mgc = mgc;
		this.mmp = mmp;
		this.content = content;
		int h = 0;
		for (Selectable item : content) {
			h = Math.max(h, item.where().bottom);
		}
		this.swm = new ScrollingWithMargin(mgc.screenHeight(), h, 64);
	}

	void draw() {
		mgc.fillRectangle(0, 0, mgc.screenWidth(), mgc.screenHeight(), COL_BACKGROUND);

		Coord mouse = mmp.screenPixels();
		Coord scroll = new Coord(0, swm.scrollPosFromScreenPos(mouse.y));
		Coord canvasMouse = mouse.add2(scroll);
		System.out.println(String.format("mouse%s scroll%s canvas%s", mouse, scroll, canvasMouse));

		hover = -1;
		int p = 0;
		for (Selectable item : content) {
			Box where = item.where().copy();
			where.sub(scroll);
			boolean isHover = where.inside(mouse);
			item.draw(mgc, where);
			if (isHover) {
				mgc.drawBox(where.left, where.top, where.width(), where.height(), mgc.process(COL_CURRENT_BLOCK));
				hover = p;
			}
			p++;
		}
	}

	void start() {
		savePosition = mmp.setScreenPixels(ourPosition);
	}

	public int getHover() {
		return hover;
	}

	public void setHover(int h) {
		Coord canvasPos = content.get(h).where().middle();
		ourPosition = new Coord(canvasPos.x, swm.screenPosFromCanvasPos(canvasPos.y));
	}

	void end() {
		ourPosition = mmp.setScreenPixels(savePosition);
	}
}
