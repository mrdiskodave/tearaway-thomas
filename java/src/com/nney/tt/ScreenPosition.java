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

	private final ScreenOrdinate scrOrdX;
	private final ScreenOrdinate scrOrdY;

	private Box mapLimits;

	private int leftLimit;

	private int rightLimit;

	public ScreenPosition(int screenWidth, int screenHeight, Coord centre) {
		this.screenWidth = screenWidth;
		this.screenHeight = screenHeight;
		this.scrOrdX = new ScreenOrdinate("X", screenWidth, centre.x);
		this.scrOrdY = new ScreenOrdinate("Y", screenHeight, centre.y);
	}

	public void setMapBoundsInPixels(Box scrollLimits, Box mapLimits) {
		this.mapLimits = mapLimits.copy();
		scrOrdX.setConstraints(mapLimits.left, mapLimits.width(), scrollLimits.left, scrollLimits.width());
		scrOrdY.setConstraints(mapLimits.top, mapLimits.height(), scrollLimits.top, scrollLimits.height());
		leftLimit = mapLimits.left + 6;
		rightLimit = mapLimits.right - 6;

		calculateScreenDisplayInformation();
	}

	private void calculateScreenDisplayInformation() {
		screen.x = scrOrdX.calculateScreenDrawingInformation();
		screen.y = scrOrdY.calculateScreenDrawingInformation();
	}

	/**
	 * Get where the top left of the screen is.
	 * 
	 * @return
	 */
	public Coord position() {
		return screen;
	}

	/**
	 * Set where the top left of the screen is.
	 * 
	 * @param c
	 */
	public void position(Coord c) {
		scrOrdX.set(c.x);
		scrOrdY.set(c.y);
		calculateScreenDisplayInformation();
	}

	/**
	 * Scroll the centre of the screen gently towards the given position.
	 */
	public void scrollTo(Coord c) {
		scrOrdX.scrollTo(c.x);
		scrOrdY.scrollTo(c.y);
		calculateScreenDisplayInformation();
	}

	/**
	 * Snap the centre of the screen screen instantly to the given position.
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
	// not convinced these screen-drawing routines belong here.
	//
	// the methods above are just concerned with tracking
	// the screen position.
	//

	public void drawTheMap(GameMap gameMap, BlockSet blockSet) {
		ScreenOrdinate ox = scrOrdX;
		ScreenOrdinate oy = scrOrdY;

		// ox.show();
		// System.out.println(gameMap.boundsInBlocks());

		int[] blockRow = new int[ox.sdiBlockCount];
		int pixelDestY = oy.sdiInitialPixelDestination;
		for (int loopY = 0; loopY < oy.sdiBlockCount; loopY++) {
			for (int loopX = 0; loopX < ox.sdiBlockCount; loopX++) {
				blockRow[loopX] = gameMap
						.fastGetBlock(ox.sdiMapSourceInBlocks + loopX, oy.sdiMapSourceInBlocks + loopY);
			}
			blockSet.blocksHolder.draw(blockRow, ox.sdiInitialPixelDestination, pixelDestY);
			pixelDestY += Const.BLOCK_SIZE;
		}
	}

	private static final int BORDER_COLOR = 0xff000000;

	public void drawBorders(GraphicsContext gc) {
		int sw = gc.screenWidth();
		int sh = gc.screenHeight();
		{
			ScreenOrdinate ox = scrOrdX;
			if (ox.sdiInitialPixelDestination > 0) {
				gc.fillRectangle(0, 0, ox.sdiInitialPixelDestination, sh, BORDER_COLOR);
			}
			if (ox.sdiHighBorderStart < sw) {
				gc.fillRectangle(ox.sdiHighBorderStart, 0, sw, sh, BORDER_COLOR);
			}
		}
		{
			ScreenOrdinate oy = scrOrdY;
			if (oy.sdiInitialPixelDestination > 0) {
				gc.fillRectangle(0, 0, sw, oy.sdiInitialPixelDestination, BORDER_COLOR);
			}
			if (oy.sdiHighBorderStart < sh) {
				gc.fillRectangle(0, oy.sdiHighBorderStart, sw, sh, BORDER_COLOR);
			}
		}
	}

	public void drawGrid(GraphicsContext gc) {
		ScreenOrdinate ox = scrOrdX;
		ScreenOrdinate oy = scrOrdY;
		int col = 0x40ffffff;

		{
			int dx = ox.sdiInitialPixelDestination;
			int s = ox.sdiBlockCount * Const.BLOCK_SIZE;
			for (int q = 0; q < oy.sdiBlockCount; q++) {
				int dy = oy.sdiInitialPixelDestination + q * Const.BLOCK_SIZE;
				gc.fillRectangle(dx, dy, s, 1, col);
				gc.fillRectangle(dx, dy + Const.BLOCK_SIZE - 1, s, 1, col);
			}
		}
		{
			int dy = oy.sdiInitialPixelDestination;
			int s = oy.sdiBlockCount * Const.BLOCK_SIZE;
			for (int q = 0; q < ox.sdiBlockCount; q++) {
				int dx = ox.sdiInitialPixelDestination + q * Const.BLOCK_SIZE;
				gc.fillRectangle(dx, dy, 1, s, col);
				gc.fillRectangle(dx + Const.BLOCK_SIZE - 1, dy, 1, s, col);
			}
		}
	}

}
