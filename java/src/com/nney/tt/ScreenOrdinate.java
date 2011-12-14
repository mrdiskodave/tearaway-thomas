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
	 * Where to start writing the graphics block? (a screen ordinate in pixels)
	 */
	public int outInitialPixelDestination;

	/**
	 * Where to start reading the block numbers? (a map ordinate in blocks)
	 */
	public int outMapSourceInBlocks;

	/**
	 * How many blocks to process? (a count in blocks)
	 */
	public int outBlockCount;

	/**
	 * initialPixelDestination + blockCount * Const.BLOCK_SIZE
	 */
	public int outHighBorderStart;

	private int screenSize;

	private int mapStart;

	private int mapSize;

	private int scrollStart;

	private int scrollSpare;

	private int screenCentre;

	@SuppressWarnings("unused")
	private final String name;

	public ScreenOrdinate(String name) {
		this.name = name;
	}

	public void snapTo(int dest) {
		set(dest - screenCentre);
	}

	public void scrollTo(int dest) {
		set(current + shrinkDelta(dest - screenCentre - current));
	}

	/**
	 * Limit the given ordinate.
	 * 
	 * @param current
	 *            The ordinate as we'd like it.
	 * @return The ordinate cropped so it doesn't go outside of the visible
	 *         area.
	 */
	public void set(int position) {
		if (scrollSpare < 0) {
			// less than the screen ... so we see all of it (centered)
			// the given position is ignored!
			current = mapStart + scrollSpare / 2;
		}
		else {
			// more than the screen ... so we see some of it
			// we check the given position to make sure it is within given
			// constraints.
			// System.out.println(String.format("%s = %s-%s result %s", name,
			// inScrollStart,
			// inScrollStart + inScrollSpare, current));
			current = Math2.limit(scrollStart, scrollStart + scrollSpare, position);
			// System.out.println(String.format("%s answer %s", name, current));

		}
	}

	/**
	 * Generate our public fields. These are exposed to support drawing of our
	 * map on the screen.
	 * 
	 * @param current
	 *            A valid ordinate i.e one has been through {@link #limit(int)}
	 * @return
	 */
	public int calculate() {
		// how would we draw the map if we had endless space?
		outInitialPixelDestination = mapStart - current;
		outMapSourceInBlocks = mapStart >> Const.BLOCK_SHIFT;
		outBlockCount = mapSize >> Const.BLOCK_SHIFT;

		// clip it low
		int l = outInitialPixelDestination / Const.BLOCK_SIZE;
		if (l < 0) {
			outInitialPixelDestination -= l * Const.BLOCK_SIZE;
			outMapSourceInBlocks -= l;
			outBlockCount += l;
		}

		// clip to high
		int r = outInitialPixelDestination - screenSize + outBlockCount * Const.BLOCK_SIZE;
		r /= Const.BLOCK_SIZE;
		if (r > 0) {
			outBlockCount -= r;
		}

		// compute a useful derived value
		outHighBorderStart = outInitialPixelDestination + outBlockCount * Const.BLOCK_SIZE;

		return current;
	}

	public void setConstraints(int mapStart, int mapSize, int scrollStart, int scrollSize) {
		this.mapStart = mapStart;
		this.mapSize = mapSize;
		this.scrollStart = scrollStart;
		this.scrollSpare = scrollSize - screenSize;
	}

	public void setCentre(int screenSize, int percent) {
		this.screenSize = screenSize;
		this.screenCentre = Math2.percent(screenSize, percent);
	}

	private static int shrinkDelta(int delta) {
		int sign = Integer.signum(delta);
		delta = Math.min(Math.abs(delta), SCROLLING_TABLE.length - 1);
		return sign * SCROLLING_TABLE[delta];
	}

}
