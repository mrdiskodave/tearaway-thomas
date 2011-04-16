package com.nney.tt;

import java.util.HashSet;
import java.util.Random;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.map.BlockSpecifications;
import com.nney.tt.map.GameMap;
import com.nney.tt.map.MasksHolder;
import com.nney.tt.sprites.LineInfo;
import com.nney.tt.sprites.Sprite;

public class World implements AlienServices {
	/**
	 * A curve of sorts that dictates how much to {@link #scrollTowards(Coord)}
	 * pulls tracked {@link Coord} back into the centre (given its distance from
	 * the centre).
	 */
	static private final int SCROLLING_TABLE[] = { 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2,
			3, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 6, 6, 6, 7, 7, 7, 8, 8, 8, 9, 9, 9, 10, 10, 11, 11, 12, 12, 13, 14, 15,
			16 };

	public Coord screen = new Coord();
	public GameMap gameMap;
	public MasksHolder maskHolder;
	public BlockSpecifications bs;
	public HashSet<Integer> keys;
	public Random rnd = new Random(5);
	public MyFont debugFont;
	public Player player;
	public MyFont font;

	public Box mapBounds;

	public int frameNumber;

	private Sprite ttSprite;

	private Coord ttPos;

	void startFrame() {
//		renderQueue.clear();
	}

	@Override
	public int randomness(int n) {
		return rnd.nextInt(n);
	}

	private int getBlock(Coord c) {
		return gameMap.getBlock(c.x / 16, c.y / 16);
	}

	private boolean inTheGround(Coord c) {
		int block = getBlock(c);
		return maskHolder.inTheGround(block, c.x & 15, c.y & 15);
	}

	@Override
	public String getBlockSpecification(Coord c) {
		int block = getBlock(c);
		return bs.get(block);
	}

	@Override
	public boolean playerFall(Coord where, int fallMax) {
		// if we are in the ground ..
		if (inTheGround(where)) {
			// raise until we are not
			do {
				where.y--;
			} while (inTheGround(where));
			return true;
		}
		else {
			int givenY = where.y;
			for (;;) {
				// otherwise fall
				where.y++;
				// but once we're in the ground
				if (inTheGround(where)) {
					// back out by one
					where.y--;
					// and we're done!
					return true;
				}
				// UNLESS we blow our maximum fallDistance
				if (--fallMax <= 0) {
					where.y = givenY;
					return false;
				}
			}
		}
	}

	/**
	 * Scroll towards the given position.
	 */
	@Override
	public void scrollTowards(Coord c) {
		screen.x = scrollOrd(screen.x, c.x - Main.SCREEN_WIDTH / 2, mapBounds.left, mapBounds.right - Main.SCREEN_WIDTH);
		screen.y = scrollOrd(screen.y, c.y - Main.SCREEN_HEIGHT * 11 / 16, mapBounds.top, mapBounds.bottom
				- Main.SCREEN_HEIGHT);
	}

	private int scrollOrd(int current, int dest, int min, int max) {
		current += shrinkDelta(dest - current);
		if (current < min) {
			current = min;
		}
		if (current > max) {
			current = max;
		}
		return current;
	}

	private int shrinkDelta(int delta) {
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

	@Override
	public boolean testKey(int key) {
		boolean answer = keys.contains(key);
		return answer;
	}

	@Override
	public void registerPlayerSpriteForAlienColisions(Coord c, Sprite s) {
		ttPos = new Coord(c);
		ttPos.x -= s.handleX;
		ttPos.y -= s.handleY;
		ttSprite = s;
	}

	@Override
	public void queueSprite(Coord c, final Sprite s) {
		final int x = c.x - screen.x;
		final int y = c.y - screen.y;
		s.draw(x, y);
	}

	@Override
	public void queueDebugText(Coord c, final String text) {
		final Coord p = new Coord(c);
		p.sub(screen);
		queueAbsoluteDebugText(p, text);
	}

	private void queueAbsoluteDebugText(final Coord p, final String text) {
		debugFont.draw(p.x, p.y, 0x0000ff, 0, text);
	}

	@Override
	public Coord getPlayerPosition() {
		return player.c;
	}

	@Override
	public void validatePlayerPosition(Coord c) {
		Box m = new Box(mapBounds);
		m.shrink(6);
		m.constrain(c);
	}

	@Override
	public int getFrameNumber() {
		return frameNumber;
	}

	@Override
	public boolean collideAlienDeluxePaintBoxWithPlayer(Coord alienPos, Box deluxePaintBox) {
		int diffX = player.c.x - alienPos.x;
		int diffY = player.c.y - alienPos.y;
	
		int deluxePaintX = 160 + diffX;
		int deluxePaintY = 128 - diffY;
		if (deluxePaintX + 8 >= deluxePaintBox.left) {
			if (deluxePaintX - 8 <= deluxePaintBox.right) {
				if (deluxePaintY <= deluxePaintBox.top) {
					if (deluxePaintY + 30 >= deluxePaintBox.bottom) {
						return true;
					}
				}
			}
		}
		return false;
	}

	@Override
	public boolean collideAlienWithPlayerBounds(Coord alienPos, Sprite alienSprite) {
		int dx = alienPos.x - alienSprite.handleX - ttPos.x;
		if (dx < ttSprite.w && dx > (-alienSprite.w)) {
			int dy = alienPos.y - alienSprite.handleY - ttPos.y;
			return dy < ttSprite.h && dy > (-alienSprite.h);
		}
		return false;
	}
	
	
	@Override
	public boolean collideAlienWithPlayerHiRes(Coord alienPos, Sprite alienSprite) {
		int dx = alienPos.x - alienSprite.handleX - ttPos.x;
		if (dx < ttSprite.w && dx > (-alienSprite.w)) {
			int dy = alienPos.y - alienSprite.handleY - ttPos.y;
			if (dy < ttSprite.h && dy > (-alienSprite.h)) {
				if (dy < 0) {
					return LineInfo.collide(alienSprite.lineInfo, ttSprite.lineInfo, -dy, dx);
				}
				else {
					return LineInfo.collide(ttSprite.lineInfo, alienSprite.lineInfo, dy, -dx);
				}
			}
		}
		return false;
	}

	@Override
	public void stunThePlayer() {
		player.stun();
	}

}
