package com.nney.tt;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;

public class ScreenPosition {
	private Coord screen = new Coord();
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

	private void limitScreenPosition() {
		Box b = liveScrollBoundsInPixels;
		screen.x = limit(screen.x, b.left, b.width(), screenWidth);
		screen.y = limit(screen.y, b.top, b.height(), screenHeight);
	}

	/**
	 * A curve of sorts that dictates how much to {@link #scrollTo(Coord)}
	 * pulls tracked {@link Coord} back into the centre (given its distance from
	 * the centre).
	 */
	static private final int SCROLLING_TABLE[] = { 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2,
			3, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 6, 6, 6, 7, 7, 7, 8, 8, 8, 9, 9, 9, 10, 10, 11, 11, 12, 12, 13, 14, 15,
			16 };

	private static int limit(int current, int playStart, int playSize, int scrSize) {
		if (playSize<scrSize) {
			current = playStart - (scrSize-playSize)/2;
			// and we'll be needing some black borders on that! TODO
		}
		else {
			if (current < playStart) {
				current = playStart;
			}
			int max = playStart + playSize - scrSize;
			if (current > max) {
				current = max;
			}
		}
		return current;
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
		return c.copyAndAdd(-screenWidth / 2, -screenHeight * 11 / 16);
	}


	private static int scrollOrd(int current, int dest) {
		current += shrinkDelta(dest - current);
		return current;
	}


	// player:
	
	/**
	 * Scroll the screen gently towards the given position.
	 */
	public void scrollTo(Coord c) {
		Coord sd = screenDest(c);
		screen.x = scrollOrd(screen.x, sd.x);
		screen.y = scrollOrd(screen.y, sd.y);
		limitScreenPosition();
	}

	/**
	 * Snap the screen instantly to the given position.
	 */
	public void snapTo(Coord c) {
		screen = screenDest(c);
		limitScreenPosition();
	}

	public void keepPlayerInView(Coord c) {
		Box m = liveScrollBoundsInPixels.copy();
		m.shrink(6);
		m.constrain(c);
	}

	
	// mapper:
	
	public Coord position() {
		return screen;
	}
	
	public void setPosition(Coord c) {
		screen = c;
		limitScreenPosition();
	}

	// fridge:
	
	public Box box() {
		return Box.fromTopLeftAndSize(screen, screenWidth, screenHeight);
	}
}
