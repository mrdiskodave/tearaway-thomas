package com.nney.tt;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.gfx.GraphicsContext;
import com.nney.tt.map.GameMap;
import com.nney.utils.Math2;

public class ScreenPosition {

	private final Coord screen = new Coord();
	private final int screenWidth;
	private final int screenHeight;

	private final ScreenOrdinate scrOrdX = new ScreenOrdinate("X");
	private final ScreenOrdinate scrOrdY = new ScreenOrdinate("Y");

	private Box mapLimits;

	private int leftLimit;

	private int rightLimit;

	public ScreenPosition(int screenWidth, int screenHeight, Coord centre) {
		this.screenWidth = screenWidth;
		this.screenHeight = screenHeight;
		scrOrdX.setCentre(screenWidth, centre.x);
		scrOrdY.setCentre(screenHeight, centre.y);
	}

	public void setMapBoundsInPixels(Box scrollLimits, Box mapLimits) {
		this.mapLimits = mapLimits.copy();
		scrOrdX.setConstraints(mapLimits.left, mapLimits.width(), scrollLimits.left, scrollLimits.width());
		scrOrdY.setConstraints(mapLimits.top, mapLimits.height(), scrollLimits.top, scrollLimits.height());
		leftLimit = mapLimits.left + 6;
		rightLimit = mapLimits.right - 6;

		// refresh scrOrdY and scrOrdY
		// snapTo(screen);
	}

	private void calculateScreenDisplayInformation() {
		screen.x = scrOrdX.calculate();
		screen.y = scrOrdY.calculate();
	}

	// player:

	public Coord position() {
		return screen;
	}

	public void position(Coord c) {
		scrOrdX.set(c.x);
		scrOrdY.set(c.y);
		calculateScreenDisplayInformation();
	}

	/**
	 * Scroll the screen gently towards the given position.
	 */
	public void scrollTo(Coord c) {
		scrOrdX.scrollTo(c.x);
		scrOrdY.scrollTo(c.y);
		calculateScreenDisplayInformation();
	}

	/**
	 * Snap the screen instantly to the given position.
	 */
	public void snapTo(Coord c) {
		scrOrdX.snapTo(c.x);
		scrOrdY.snapTo(c.y);
		calculateScreenDisplayInformation();
	}

	public int keepPlayerXInMap(int x) {
		return Math2.limit(leftLimit, rightLimit, x);
	}

	public boolean keepInMap(Coord c) {
		return mapLimits.constrain(c);
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

		// ox.show();
		// System.out.println(gameMap.boundsInBlocks());

		int[] blockRow = new int[ox.outBlockCount];
		int pixelDestY = oy.outInitialPixelDestination;
		for (int loopY = 0; loopY < oy.outBlockCount; loopY++) {
			for (int loopX = 0; loopX < ox.outBlockCount; loopX++) {
				blockRow[loopX] = gameMap.fastGetBlock(ox.outMapSourceInBlocks + loopX, oy.outMapSourceInBlocks + loopY);
			}
			blockSet.blocksHolder.draw(blockRow, ox.outInitialPixelDestination, pixelDestY);
			pixelDestY += Const.BLOCK_SIZE;
		}
	}

	private static final int BORDER_COLOR = 0xff000000;

	public void drawBorders(GraphicsContext gc) {
		int sw = gc.screenWidth();
		int sh = gc.screenHeight();
		{
			ScreenOrdinate ox = scrOrdX;
			if (ox.outInitialPixelDestination > 0) {
				gc.fillRectangle(0, 0, ox.outInitialPixelDestination, sh, BORDER_COLOR);
			}
			if (ox.outHighBorderStart < sw) {
				gc.fillRectangle(ox.outHighBorderStart, 0, sw, sh, BORDER_COLOR);
			}
		}
		{
			ScreenOrdinate oy = scrOrdY;
			if (oy.outInitialPixelDestination > 0) {
				gc.fillRectangle(0, 0, sw, oy.outInitialPixelDestination, BORDER_COLOR);
			}
			if (oy.outHighBorderStart < sh) {
				gc.fillRectangle(0, oy.outHighBorderStart, sw, sh, BORDER_COLOR);
			}
		}
	}

	public void drawGrid(GraphicsContext gc) {
		ScreenOrdinate ox = scrOrdX;
		ScreenOrdinate oy = scrOrdY;
		int col = 0x40ffffff;

		{
			int dx = ox.outInitialPixelDestination;
			int s = ox.outBlockCount * Const.BLOCK_SIZE;
			for (int q = 0; q < oy.outBlockCount; q++) {
				int dy = oy.outInitialPixelDestination + q * Const.BLOCK_SIZE;
				gc.fillRectangle(dx, dy, s, 1, col);
				gc.fillRectangle(dx, dy + Const.BLOCK_SIZE - 1, s, 1, col);
			}
		}
		{
			int dy = oy.outInitialPixelDestination;
			int s = oy.outBlockCount * Const.BLOCK_SIZE;
			for (int q = 0; q < ox.outBlockCount; q++) {
				int dx = ox.outInitialPixelDestination + q * Const.BLOCK_SIZE;
				gc.fillRectangle(dx, dy, 1, s, col);
				gc.fillRectangle(dx + Const.BLOCK_SIZE - 1, dy, 1, s, col);
			}
		}
	}

}
