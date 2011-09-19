package com.nney.tt;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;

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
	public final ScreenOrdinate scrOrdX = new ScreenOrdinate();
	public final ScreenOrdinate scrOrdY = new ScreenOrdinate();
	private final int screenWidth;
	private final int screenHeight;
	private Box liveScrollBoundsInPixels;

	public ScreenPosition(int screenWidth, int screenHeight) {
		this.screenWidth = screenWidth;
		this.screenHeight = screenHeight;
	}

	public void setWorldBoundsInPixels(Box b) {
		liveScrollBoundsInPixels = b;
	}
	
	public void setWorldBoundsInBlocks(Box b) {
		liveScrollBoundsInPixels = b.mult2(Const.BLOCK_SIZE);
	}

	public void setPosition(Coord c) {
		Box b = liveScrollBoundsInPixels;
		screen.x = scrOrdX.generate(c.x, screenWidth, b.left, b.width(), "X");
		screen.y = scrOrdY.generate(c.y, screenHeight, b.top, b.height(), "Y");
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
		return c.copyAndAdd(-screenWidth / 2, -screenHeight * 64 / 100);
	}

	private static int scrollOrd(int current, int dest) {
		return current +  shrinkDelta(dest - current);
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
		Box m = liveScrollBoundsInPixels.copy();
		m.shrink(6);
		m.constrain(c);
	}

	// everyone:

	public Coord position() {
		return screen;
	}

	// fridge:

	public Box box() {
		return Box.fromTopLeftAndSize(screen, screenWidth, screenHeight);
	}
}
