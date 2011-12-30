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
	private static final int COL_BACKGROUND = 0xff0020a0;

	private final List<Selectable> content;
	private final ScrollingWithMargin swm;
	private final MapperGC mgc;

	private int hover;

	private final SimpleMouse mmp;

	private Coord savePosition;

	private Coord ourPosition = new Coord(0, 0);

	private boolean active;

	SelectionScreen(MapperGC mgc, SimpleMouse mouse, List<Selectable> content) {
		this.mgc = mgc;
		this.mmp = mouse;
		this.content = content;
		int h = 0;
		for (Selectable item : content) {
			h = Math.max(h, item.where().bottom);
		}
		this.swm = new ScrollingWithMargin(mgc.screenHeight(), h, 64);
	}

	void draw() {
		mgc.fillRectangle(0, 0, mgc.screenWidth(), mgc.screenHeight(), COL_BACKGROUND);

		Coord mousePosition = mmp.get();
		Coord scroll = new Coord(0, swm.scrollPosFromScreenPos(mousePosition.y));
		// Coord canvasMouse = mousePosition.add2(scroll);
		// System.out.println(String.format("mouse%s scroll%s canvas%s", mouse,
		// scroll, canvasMouse));

		int p = 0;
		for (Selectable item : content) {
			Box where = item.where().copy();
			where.sub(scroll);
			boolean isHover = where.inside(mousePosition);
			item.draw(mgc, where);
			if (isHover) {
				mgc.drawBox(where.left, where.top, where.width(), where.height(), mgc.process(COL_CURRENT_BLOCK));
				hover = p;
			}
			p++;
		}
	}

	public int getHover() {
		return hover;
	}

	public void setHover(int h) {
		Coord canvasPos = content.get(h).where().middle();
		ourPosition = new Coord(canvasPos.x, swm.screenPosFromCanvasPos(canvasPos.y));
		if (active) {
			mmp.set(ourPosition);
		}
		hover = h;
	}

	public void begin() {
		savePosition = mmp.set(ourPosition);
		active = true;
	}

	public void end() {
		ourPosition = mmp.set(savePosition);
		active = false;
	}

	public void moveBy(int i) {
		setHover(getHoverRel(i));
	}

	public int getHoverRel(int i) {
		int h = getHover();
		h += content.size() * 4 + i;
		h %= content.size();
		return h;
	}

	public boolean isActive() {
		return active;
	}
}
