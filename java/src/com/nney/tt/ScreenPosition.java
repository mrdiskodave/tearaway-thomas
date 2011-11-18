package com.nney.tt;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.gfx.GraphicsContext;
import com.nney.tt.map.GameMap;
import com.nney.utils.Math2;

public class ScreenPosition {
	/**
	 * A curve of sorts that dictates how much to {@link #scrollTo(Coord)} pulls
	 * the given {@link Coord} back into the centre (given its distance from the
	 * centre).
	 */
	static private final int SCROLLING_TABLE[] = { 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2,
			3, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 6, 6, 6, 7, 7, 7, 8, 8, 8, 9, 9, 9, 10, 10, 11, 11, 12, 12, 13, 14, 15,
			16 };

	private final Coord screen = new Coord();
	private final int screenWidth;
	private final int screenHeight;

	private final ScreenOrdinate scrOrdX = new ScreenOrdinate("X");
	private final ScreenOrdinate scrOrdY = new ScreenOrdinate("Y");

	private Coord centre;

	private Box mapLimits;

	public ScreenPosition(int screenWidth, int screenHeight, Coord centre) {
		this.screenWidth = screenWidth;
		this.screenHeight = screenHeight;
		int cx = Math2.percent(screenWidth, centre.x);
		int cy = Math2.percent(screenHeight, centre.y);
		this.centre = new Coord(cx, cy);
	}

	public void setMapBoundsInPixels(Box scrollLimits, Box mapLimits) {
		this.mapLimits = mapLimits.copy();
		scrOrdX.setConstraints(screenWidth, mapLimits.left, mapLimits.width(), scrollLimits.left, scrollLimits.width(),
				"X");
		scrOrdY.setConstraints(screenHeight, mapLimits.top, mapLimits.height(), scrollLimits.top,
				scrollLimits.height(), "Y");
	}

	public void setPosition(Coord c) {
		screen.x = scrOrdX.generate(c.x);
		screen.y = scrOrdY.generate(c.y);
	}

	private static int shrinkDelta(int delta) {
		boolean neg = false;
		if (delta < 0) {
			neg = true;
			delta = -delta;
		}
		delta = Math.min(delta, SCROLLING_TABLE.length - 1);
		int shrunkDelta = SCROLLING_TABLE[delta];
		if (neg) {
			shrunkDelta = -shrunkDelta;
		}
		return shrunkDelta;

	}

	private Coord screenDest(Coord c) {
		return c.sub2(centre);
	}

	private static int scrollOrd(int current, int dest) {
		return current + shrinkDelta(dest - current);
	}

	// player:

	/**
	 * Scroll the screen gently towards the given position.
	 */
	public void scrollTo(Coord c) {
		Coord sd = screenDest(c);
		setPosition(new Coord(scrollOrd(screen.x, sd.x), scrollOrd(screen.y, sd.y)));
	}

	/**
	 * Snap the screen instantly to the given position.
	 */
	public void snapTo(Coord c) {
		setPosition(screenDest(c));
	}

	public void keepPlayerInMap(Coord c) {
		Box m = mapLimits.copy();
		m.shrink(6);
		m.constrain(c);
	}
	
	public boolean keepInMap(Coord c) {
		return mapLimits.constrain(c);
	}

	public Coord position() {
		return screen;
	}

	public Box box() {
		return Box.fromTopLeftAndSize(screen, screenWidth, screenHeight);
	}

	// ----------------------------------------------------------------------------------------------------
	// DRAWING
	//
	// not convinced these screen-drawing routines belong here
	//
	// the whole rest of this class is otherwise concerned with
	// just working out where the screen and borders are located
	//

	public void drawTheMap(GameMap gameMap, BlockSet blockSet) {
		ScreenOrdinate ox = scrOrdX;
		ScreenOrdinate oy = scrOrdY;

		int[] blockRow = new int[ox.blockCount];
		int pixelDestY = oy.initialPixelDestination;
		for (int loopY = 0; loopY < oy.blockCount; loopY++) {
			for (int loopX = 0; loopX < ox.blockCount; loopX++) {
				blockRow[loopX] = gameMap.fastGetBlock(ox.mapSourceInBlocks + loopX, oy.mapSourceInBlocks + loopY);
			}
			blockSet.blocksHolder.draw(blockRow, ox.initialPixelDestination, pixelDestY);
			pixelDestY += Const.BLOCK_SIZE;
		}
	}

	private static final int BORDER_COLOR = 0xff000000;

	public void drawBorders(GraphicsContext gc) {
		int sw = gc.screenWidth();
		int sh = gc.screenHeight();
		{
			ScreenOrdinate ox = scrOrdX;
			if (ox.initialPixelDestination > 0) {
				gc.fillRectangle(0, 0, ox.initialPixelDestination, sh, BORDER_COLOR);
			}
			if (ox.highBorderStart < sw) {
				gc.fillRectangle(ox.highBorderStart, 0, sw, sh, BORDER_COLOR);
			}
		}
		{
			ScreenOrdinate oy = scrOrdY;
			if (oy.initialPixelDestination > 0) {
				gc.fillRectangle(0, 0, sw, oy.initialPixelDestination, BORDER_COLOR);
			}
			if (oy.highBorderStart < sh) {
				gc.fillRectangle(0, oy.highBorderStart, sw, sh, BORDER_COLOR);
			}
		}
	}

	public void drawGrid(GraphicsContext gc) {
		ScreenOrdinate ox = scrOrdX;
		ScreenOrdinate oy = scrOrdY;
		int col = 0x40ffffff;

		{
			int dx = ox.initialPixelDestination;
			int s = ox.blockCount * Const.BLOCK_SIZE;
			for (int q = 0; q < oy.blockCount; q++) {
				int dy = oy.initialPixelDestination + q * Const.BLOCK_SIZE;
				gc.fillRectangle(dx, dy, s, 1, col);
				gc.fillRectangle(dx, dy + Const.BLOCK_SIZE - 1, s, 1, col);
			}
		}
		{
			int dy = oy.initialPixelDestination;
			int s = oy.blockCount * Const.BLOCK_SIZE;
			for (int q = 0; q < ox.blockCount; q++) {
				int dx = ox.initialPixelDestination + q * Const.BLOCK_SIZE;
				gc.fillRectangle(dx, dy, 1, s, col);
				gc.fillRectangle(dx + Const.BLOCK_SIZE - 1, dy, 1, s, col);
			}
		}
	}

}
