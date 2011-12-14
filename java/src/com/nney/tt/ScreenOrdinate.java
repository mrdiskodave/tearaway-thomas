package com.nney.tt;

import com.nney.utils.Math2;

/**
 * There will be two instances of this class - one for the X ordinate and one
 * for the Y ordinate. It deals with per-ordinate position validation and
 * per-ordinate calculations required for drawing the map. They've everything in
 * common there is no sense in coding it twice.
 */
public class ScreenOrdinate {
	/**
	 * A curve of sorts that dictates how much to {@link #scrollTo(int)} pulls
	 * an orderinate back into the centre (given its distance from the centre).
	 */
	static private final int SCROLLING_TABLE[] = { 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2,
			3, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 6, 6, 6, 7, 7, 7, 8, 8, 8, 9, 9, 9, 10, 10, 11, 11, 12, 12, 13, 14, 15,
			16 };

	/**
	 * Where is this screen ordinate now?
	 */
	private int current;

	/**
	 * Screen Drawing Information:<br>
	 * Where to start writing the graphics block? (a screen ordinate in pixels)
	 */
	public int sdiInitialPixelDestination;

	/**
	 * Screen Drawing Information:<br>
	 * Where to start reading the block numbers? (a map ordinate in blocks)
	 */
	public int sdiMapSourceInBlocks;

	/**
	 * Screen Drawing Information:<br>
	 * How many blocks to process? (a count in blocks)
	 */
	public int sdiBlockCount;

	/**
	 * Screen Drawing Information:<br>
	 * The first undrawn pixel
	 */
	public int sdiHighBorderStart;

	/**
	 * Screen size in pixels.
	 */
	final private int screenSize;

	/**
	 * Map size in pixels.
	 */
	private int mapSize;

	/**
	 * The lowest permissible map ordinate.
	 */
	private int mapLowest;

	/**
	 * The lowest permissible scroll ordinate.
	 */
	private int scrollLowest;

	/**
	 * How much space do we have for scrolling?
	 */
	private int scrollSpace;

	/**
	 * Centre ordinate in pixels (that {@link #snapTo(int)} and
	 * {@link #scrollTo(int)} use).
	 */
	final private int screenCentre;

	/**
	 * Our name (for debug purposes).
	 */
	@SuppressWarnings("unused")
	private final String name;

	public ScreenOrdinate(String name, int screenSize, int percent) {
		this.name = name;
		this.screenSize = screenSize;
		this.screenCentre = Math2.percent(screenSize, percent);
	}

	/**
	 * Jump the centre of the screen to the given location.
	 * 
	 * @param dest
	 *            An ordinate in pixels.
	 */
	public void snapTo(int dest) {
		set(dest - screenCentre);
	}

	/**
	 * Scroll the centre of the screen to the given location.
	 * 
	 * @param dest
	 *            An ordinate in pixels.
	 */

	public void scrollTo(int dest) {
		set(current + shrinkDelta(dest - screenCentre - current));
	}

	/**
	 * Set the top-left of the screen to the given location.
	 * 
	 * @param dest
	 *            An ordinate in pixels.
	 */
	public void set(int dest) {
		if (scrollSpace <= 0) {
			// less than the screen ... so we see all of it (centered)
			// the given dest is ignored:
			current = mapLowest + scrollSpace / 2;
		}
		else {
			// more than the screen ... so we see some of it
			current = Math2.limit(scrollLowest, scrollLowest + scrollSpace, dest);
		}
	}

	/**
	 * Generate our public fields. These are exposed to support drawing of our
	 * map on the screen. This method also doubles as a getter for our current
	 * ordinate.
	 * 
	 * @return Our current ordinate.
	 */
	public int calculateScreenDrawingInformation() {
		// how would we draw the map if we had endless space?
		sdiInitialPixelDestination = mapLowest - current;
		sdiMapSourceInBlocks = mapLowest >> Const.BLOCK_SHIFT;
		sdiBlockCount = mapSize >> Const.BLOCK_SHIFT;

		// clip it low
		int l = sdiInitialPixelDestination / Const.BLOCK_SIZE;
		if (l < 0) {
			sdiInitialPixelDestination -= l * Const.BLOCK_SIZE;
			sdiMapSourceInBlocks -= l;
			sdiBlockCount += l;
		}

		// clip to high
		int r = sdiInitialPixelDestination - screenSize + sdiBlockCount * Const.BLOCK_SIZE;
		r /= Const.BLOCK_SIZE;
		if (r > 0) {
			sdiBlockCount -= r;
		}

		// compute a useful derived value
		sdiHighBorderStart = sdiInitialPixelDestination + sdiBlockCount * Const.BLOCK_SIZE;

		return current;
	}

	public void setConstraints(int mapLowest, int mapSize, int scrollLowest, int scrollSize) {
		this.mapLowest = mapLowest;
		this.mapSize = mapSize;
		this.scrollLowest = scrollLowest;
		this.scrollSpace = scrollSize - screenSize;
	}

	private static int shrinkDelta(int delta) {
		int sign = Integer.signum(delta);
		delta = Math.min(Math.abs(delta), SCROLLING_TABLE.length - 1);
		return sign * SCROLLING_TABLE[delta];
	}

}
