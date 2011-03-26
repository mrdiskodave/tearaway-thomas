package com.nney;

import java.util.HashMap;
import java.util.HashSet;

import org.lwjgl.util.vector.Vector;

public class World {

	/**
	 * A curve of sorts that dictates how much to {@link #scrollTowards(Coord)}
	 * pulls tracked {@link Coord} back into the centre (given its distance from
	 * the centre).
	 */
	static private final int SCROLLING_TABLE[] = { 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
			1, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 6, 6, 6, 7, 7, 7, 8, 8, 8, 9,
			9, 9, 10, 10, 11, 11, 12, 12, 13, 14, 15, 16 };

	public Coord screen = new Coord();
	public GameMap gameMap;
	public MasksHolder maskHolder;

	public HashSet<Integer> keys;

	public HashMap<SpriteName, Sprite> spriteDict;

	public boolean inTheGround(Coord c) {
		int block = gameMap.getBlock(c.x / 16, c.y / 16);
		return maskHolder.inTheGround(block, c.x & 15, c.y & 15);
	}

	/**
	 * Interact with the ground.
	 * 
	 * @param where
	 *            Where we're at.
	 * @param fallMax
	 *            The called-defined limit on falling (in pixels).
	 * @return Are we falling? <code>true</code> meaning "yes" or
	 *         <code>false</code> meaning "no" we aren't falling we are resting
	 *         exactly one pixel above the ground.
	 */
	public boolean fallOrRaise(Coord where, int fallMax) {
		// if we are in the ground ..
		if (inTheGround(where)) {
			// raise until we are not
			do {
				where.y--;
			} while (inTheGround(where));
			return false;
		}
		else {
			for (;;) {
				// otherwise fall
				where.y++;
				// but once we're in the ground
				if (inTheGround(where)) {
					// back out by one
					where.y--;
					// and we're done!
					return false;
				}
				// UNLESS we blow our maximum fallDistance
				if (--fallMax <= 0) {
					return true;
				}
			}
		}
	}

	/**
	 * Scroll towards the given position.
	 */
	public void scrollTowards(Coord c) {
		Coord target = new Coord(Main.SCREEN_WIDTH / 2, Main.SCREEN_HEIGHT * 11 / 16);

		Coord d = new Coord(c);
		d.sub(target);
		// difference
		d.sub(screen);

		screen.x += moveBy(d.x);
		screen.y += moveBy(d.y);
	}

	private int moveBy(int x) {
		boolean neg = false;
		if (x < 0) {
			neg = true;
			x = -x;
		}
		x = Math.min(x, SCROLLING_TABLE.length - 1);
		int answer = SCROLLING_TABLE[x];
		if (neg) {
			answer = -answer;
		}
		return answer;
	}
	
	public boolean testKey(int key) {
		boolean answer = keys.contains(key);
		return answer;
	}

	public void drawAlien(Coord c, SpriteName next) {
		Sprite s = spriteDict.get(next);
		s.draw(c.x-screen.x, c.y-screen.y);		
	}
}
