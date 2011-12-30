package com.nney.tt.mapper;

import java.util.List;

import com.nney.tt.BoundedUtils;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;

public class SelectionScreen {
	/**
	 * There is a zone in the middle that decides how much we scroll according
	 * to where the mouse is within it. We have {@link #SCROLL_MARGIN} pixels of
	 * non-zone at the top and bottom because it isn't nice if the new screen is
	 * turning up <b>just</b> as the mouse reaches the top (or bottom) of the
	 * screen.
	 */
	private static final int SCROLL_MARGIN = 64;

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

	private final SimpleMouse mouse;

	private Coord savePosition;

	private Coord ourPosition = new Coord(0, 0);

	private boolean active;

	private Box bounds;

	SelectionScreen(MapperGC mgc, SimpleMouse mouse, List<Selectable> content) {
		this.mgc = mgc;
		this.mouse = mouse;
		this.content = content;
		int h = 0;
		for (Selectable item : content) {
			h = Math.max(h, item.getBounds().bottom);
		}
		this.swm = new ScrollingWithMargin(mgc.screenHeight(), h, SCROLL_MARGIN);
		bounds = BoundedUtils.collect(content);
	}

	void draw() {
		ourPosition = mouse.get();

		mgc.fillRectangle(0, 0, mgc.screenWidth(), mgc.screenHeight(), COL_BACKGROUND);

		Coord scroll = new Coord(0, swm.scrollPosFromScreenPos(ourPosition.y));
		// Coord canvasMouse = mousePosition.add2(scroll);
		// System.out.println(String.format("mouse%s scroll%s canvas%s", mouse,
		// scroll, canvasMouse));

		idraw(scroll);
	}

	public void drawCorner(Box corner) {
		// TODO: ??????????????????????????
	}

	public void idraw(Coord scroll) {
		for (int p = 0; p < content.size(); p++) {
			Selectable item = content.get(p);
			Box where = item.getBounds().sub2(scroll);
			item.draw(mgc, where);
			if (where.inside(ourPosition)) {
				mgc.drawBox(where.left, where.top, where.width(), where.height(), mgc.process(COL_CURRENT_BLOCK));
				hover = p;
			}
		}
	}

	public int getHover() {
		return hover;
	}

	public void setHover(int h) {
		Coord canvasPos = content.get(h).getBounds().middle();
		ourPosition = new Coord(canvasPos.x, swm.screenPosFromCanvasPos(canvasPos.y));
		if (active) {
			mouse.set(ourPosition);
		}
		hover = h;
	}

	public void begin() {
		savePosition = mouse.set(ourPosition);
		active = true;
	}

	public void end() {
		ourPosition = mouse.set(savePosition);
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
