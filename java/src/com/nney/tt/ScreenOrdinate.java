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
	 * Where to start writing the graphics block? (a screen ordinate in pixels)
	 */
	public int initialPixelDestination;

	/**
	 * Where to start reading the block numbers? (a map ordinate in blocks)
	 */
	public int mapSourceInBlocks;

	/**
	 * How many blocks to process? (a count in blocks)
	 */
	public int blockCount;

	void show() {
		System.out.println(String.format("%s initialPixelDestination=%d mapSourceInBlocks=%d blockCount=%d", name,
				initialPixelDestination, mapSourceInBlocks, blockCount));
	}

	/**
	 * initialPixelDestination + blockCount * Const.BLOCK_SIZE
	 */
	public int highBorderStart;

	private int inScreenSize;

	private int inMapStart;

	private int inMapSize;

	private int inScrollStart;

	private int inScrollSpare;

	@SuppressWarnings("unused")
	private final String name;

	public ScreenOrdinate(String name) {
		this.name = name;
	}

	/**
	 * Limit the given ordinate.
	 * 
	 * @param current
	 *            The ordinate as we'd like it.
	 * @return The ordinate cropped so it doesn't go outside of the visible
	 *         area.
	 */
	private int limit(int current) {
		if (inScrollSpare < 0) {
			// less than the screen ... so we see all of it (centered)
			// the given position is ignored!
			current = inMapStart + inScrollSpare / 2;
		}
		else {
			// more than the screen ... so we see some of it
			// we check the given position to make sure it is within given
			// constraints.
			current = Math2.limit(inScrollStart, inScrollStart + inScrollSpare, current);
		}
		return current;
	}

	/**
	 * Generate our public fields. These are exposed to support drawing of our
	 * map on the screen.
	 * 
	 * @param current
	 *            A valid ordinate i.e one has been through {@link #limit(int)}
	 */
	private void calculate(int current) {
		// how would we draw the map if we had endless space?
		initialPixelDestination = inMapStart - current;
		mapSourceInBlocks = inMapStart >> Const.BLOCK_SHIFT;
		blockCount = inMapSize >> Const.BLOCK_SHIFT;

		// clip it low
		int l = initialPixelDestination / Const.BLOCK_SIZE;
		if (l < 0) {
			initialPixelDestination -= l * Const.BLOCK_SIZE;
			mapSourceInBlocks -= l;
			blockCount += l;
		}

		// clip to high
		int r = initialPixelDestination - inScreenSize + blockCount * Const.BLOCK_SIZE;
		r /= Const.BLOCK_SIZE;
		if (r > 0) {
			blockCount -= r;
		}

		// compute a useful derived value
		highBorderStart = initialPixelDestination + blockCount * Const.BLOCK_SIZE;
	}

	public int generate(int current) {
		current = limit(current);
		calculate(current);
		return current;
	}

	public void setConstraints(int screenSize, int mapStart, int mapSize, int scrollStart, int scrollSize, String name) {
		this.inScreenSize = screenSize;
		this.inMapStart = mapStart;
		this.inMapSize = mapSize;
		this.inScrollStart = scrollStart;
		this.inScrollSpare = scrollSize - screenSize;
	}
}
