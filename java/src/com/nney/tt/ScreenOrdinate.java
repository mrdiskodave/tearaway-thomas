package com.nney.tt;

import com.nney.tt.map.GameMap;
import com.nney.utils.Math2;

/**
 * Before drawing the {@link GameMap} we generate one of these per ordinate
 * (i.e. one for X and one for Y). They've everything in common there is no
 * sense in coding it twice.
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

	/**
	 * initialPixelDestination + blockCount * Const.BLOCK_SIZE 
	 */
	public int highBorderStart;
	
	
	
	
	private int inScreenSize;

	private int inMapStart;

	private int inMapSize;

	@SuppressWarnings("unused")
	private final String name;


	private int inScrollStart;

	private int inScrollSpare;

	public ScreenOrdinate(String name) {
		this.name = name;
	}

	/**
	 * Make sure given current position is valid and also generate the other
	 * field data in this object. There will be two instances of this class -
	 * one for the X ordinate and one for the Y ordinate. <b>All parameters are
	 * in pixels</b>.
	 * 
	 * @param current
	 *            The current position (a map ordinate).
	 * @param inScreenSize
	 *            How big is the screen?
	 * @param inMapStart
	 *            Where does the viewable map begin?
	 * @param inMapSize
	 *            How big is the map?
	 * @param name
	 *            The name of this ordinate (for debug purposes).
	 * @return A validated position to use in place of the first parameter.
	 */
	public int limit(int current) {
		if (inScrollSpare<0) {
			// less than the screen ... so we see all of it (centered)
			// the given position is ignored!
			current = inMapStart + inScrollSpare/2;
		}
		else {
			// more than the screen ... so we see some of it
			// we check the given position to make sure it is within given constraints.
			current = Math2.limit(inScrollStart, inScrollStart + inScrollSpare, current); 
		}
		return current;
	}

	public void calc(int current) {
		initialPixelDestination = inMapStart - current;
		mapSourceInBlocks = inMapStart / Const.BLOCK_SIZE;
		blockCount = inMapSize / Const.BLOCK_SIZE;

		int l = initialPixelDestination / Const.BLOCK_SIZE;
		if (l < 0) {
			initialPixelDestination -= l * Const.BLOCK_SIZE;
			mapSourceInBlocks -= l;
			blockCount += l;
		}
		
		int r = initialPixelDestination - inScreenSize + blockCount * Const.BLOCK_SIZE;
		r /= Const.BLOCK_SIZE;
		if (r>0) {
			blockCount -= r;
		}

		highBorderStart = initialPixelDestination + blockCount * Const.BLOCK_SIZE;

//		System.out.println(String.format("%s dest%d map%d-%d (cl%d cr%d)", name, initialPixelDestination, mapSourceInBlocks,
//				blockCount, l, r));
	}

	public int generate(int current) {
		current = limit(current);
		calc(current);
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
