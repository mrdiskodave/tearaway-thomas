package com.nney.tt;

import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;

import com.nney.tt.aliens.Alien;
import com.nney.tt.aliens.MagicDustAlien;
import com.nney.tt.aliens.ScoreNoticeAlien;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.map.BlockInformation;
import com.nney.tt.map.GameMap;
import com.nney.tt.map.MasksHolder;
import com.nney.tt.sprites.LineInfo;
import com.nney.tt.sprites.Sprite;

public class World implements AlienServices, Joystick {
	/**
	 * A curve of sorts that dictates how much to {@link #scrollScreenTo(Coord)}
	 * pulls tracked {@link Coord} back into the centre (given its distance from
	 * the centre).
	 */
	static private final int SCROLLING_TABLE[] = { 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2,
			3, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 6, 6, 6, 7, 7, 7, 8, 8, 8, 9, 9, 9, 10, 10, 11, 11, 12, 12, 13, 14, 15,
			16 };


	private List<Alien> backgroundAlienList = new LinkedList<Alien>();
	private List<Alien> foregroundAlienList = new LinkedList<Alien>();
	private List<Alien> freshAlienList = new LinkedList<Alien>();

	private Fridge<Alien> freezeTop = new Fridge<Alien>("top");
	private Fridge<Alien> freezeBottom = new Fridge<Alien>("bottom");
	private Fridge<Alien> freezeLeft = new Fridge<Alien>("left");
	private Fridge<Alien> freezeRight = new Fridge<Alien>("right");


	
	public Coord screen = new Coord();
	public GameMap gameMap;
	public MasksHolder maskHolder;
	public BlockInformation bi;
	public Random rnd = new Random(5);
	public MyFont debugFont;
	public Player player;
	public MyFont font;

	public Box mapBounds;

	public int frameNumber;

	private Sprite ttSprite;

	private Coord ttPos;

	private int joystick;

	private int joystickAA;

	public LadderInfo ladderInfo;


	private int score = 0;
	private int oldScore = -1;


	private PrerenderedText scoreHeadingText;


	private PrerenderedText scoreText;

	public AlienInfoMap aim;



	@Override
	public int randomness(int n) {
		return rnd.nextInt(n);
	}

	private int getBlock(Coord c) {
		return gameMap.getBlock(c.x / 16, c.y / 16);
	}

	@Override
	public boolean inTheGround(Coord c) {
		int block = getBlock(c);
		return maskHolder.inTheGround(block, c.x & 15, c.y & 15);
	}

	/**
	 * What is there?
	 * 
	 * @param where
	 *            The pixel location being queried.
	 * @return The kind of block that is there. e.g. "magic" or "ladder" or any
	 *         text string used in the configuration of a
	 *         {@link BlockInformation} object.
	 */
	private String getBlockInfo(Coord c) {
		int block = getBlock(c);
		return bi.get(block);
	}

	@Override
	public boolean blockInfoIs(Coord c, String name) {
		String s = getBlockInfo(c);
		// System.out.println(String.format("Is %s really %s", s, name));
		return s != null && s.equals(name);
	}

	@Override
	public String blockInfoHas(Coord c, String prefix) {
		String s = getBlockInfo(c);
		if (s==null || !s.startsWith(prefix)) return null;
		return s.substring(prefix.length());
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

	// ===========================================================================
	// Scrolling
	// ===========================================================================

	private static int limit(int current, int min, int max) {
		if (current < min) {
			current = min;
		}
		if (current > max) {
			current = max;
		}
		return current;
	}

	private void limitScreenPosition() {
		screen.x = limit(screen.x, mapBounds.left, mapBounds.right - Main.SCREEN_WIDTH);
		screen.y = limit(screen.y, mapBounds.top, mapBounds.bottom - Main.SCREEN_HEIGHT);
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

	private static Coord screenDest(Coord c) {
		return c.copyAndMove(-Main.SCREEN_WIDTH / 2, -Main.SCREEN_HEIGHT * 11 / 16);
	}

	private static int scrollOrd(int current, int dest) {
		current += shrinkDelta(dest - current);
		return current;
	}

	/**
	 * Scroll the screen gently towards the given position.
	 */
	@Override
	public void scrollScreenTo(Coord c) {
		Coord sd = screenDest(c);
		screen.x = scrollOrd(screen.x, sd.x);
		screen.y = scrollOrd(screen.y, sd.y);
		limitScreenPosition();
	}

	/**
	 * Snap the screen instantly to the given position.
	 */
	@Override
	public void snapScreenTo(Coord c) {
		screen = screenDest(c);
		limitScreenPosition();
	}

	// ===========================================================================

	@Override
	public void queueSprite(final Coord c, final Sprite s) {
		queueSprite(c, s, false);
	}

	@Override
	public void queueSprite(Coord c, final Sprite s, boolean drawWhite) {
		final int x = c.x - screen.x;
		final int y = c.y - screen.y;
		s.draw(x, y, drawWhite);
	}

	@Override
	public void queueDebugText(Coord c, final String text) {
		final Coord p = c.copy();
		p.sub(screen);
		queueAbsoluteDebugText(p, text);
	}

	private void queueAbsoluteDebugText(final Coord p, final String text) {
		debugFont.draw(p.x, p.y, 0x0000ff, 0, text);
	}

	// ===========================================================================

	@Override
	public void registerPlayerSpriteForAlienColisions(Coord c, Sprite s) {
		ttPos = c.copy();
		ttPos.x -= s.handleX;
		ttPos.y -= s.handleY;
		ttSprite = s;
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
	public Player getThePlayer() {
		return player;
	}

	@Override
	public Joystick getStick() {
		return this;
	}

	@Override
	public boolean test(int mask) {
		return (mask & joystick) != 0;
	}

	@Override
	public boolean testAntiAutofire(int mask) {
		return (mask & joystickAA) != 0;
	}

	void setJoystickPosition(int next) {
		int last = joystick;
		joystick = next;
		joystickAA = next & ~last;
	}

	@Override
	public LadderInfo getLadderInfo() {
		return ladderInfo;
	}

	@Override
	public boolean frameTest(int mask, int lessThan) {
		return (getFrameNumber()&(mask-1))<lessThan;
	}
	
	@Override
	public boolean fall(Coord c, int fallSpeed) {
		for (int x=0; x<fallSpeed; x++) {
			c.y++;
			if (inTheGround(c)) {
				c.y--;
				return true;
			}
		}
		return false;
	}
	
	private void addNewAlien(Alien alien) {
		aim.connectAnims(alien);
		alien.srv = this;
		alien.init();
		freshAlienList.add(alien);
	}
	
	@Override
	public void giveScore(int amount, Coord location) {
		score += amount;
		if (location!=null) {
			addNewAlien(new ScoreNoticeAlien(amount, location.copy()));
		}
	}

	@Override
	public void magicDust(Coord location) {
		addNewAlien(new MagicDustAlien(location.copy()));
	}

	
	public void updateAliens() {
		// add fresh aliens
		for (Alien alien: freshAlienList) {
			addAlien(alien);
		}
		freshAlienList.clear();
		
		Box screenBox = Box.fromTopLeftAndSize(screen, Main.SCREEN_WIDTH, Main.SCREEN_HEIGHT);
		defrostAny(screenBox);

		updateAliens(backgroundAlienList, screenBox);
		player.draw();
		updateAliens(foregroundAlienList, screenBox);

		//
		// Caveat1: only the background Alien gets to move the player around.
		// Caveat2: if any Alien does move him the scrolling for this frame
		// won't know about it (because it has already happened) but you don't
		// notice that because it is not hard scrolling but scrolling based on a
		// SCROLLING_TABLE.
		//
		// The Amiga version had Caveat2 (even if we didn't think about it).
		// The Amiga version did not have Caveat1 because the player was beamed
		// in last of all with some Amiga hardware-sprite wizardry.
		//
		// ... well, it's either that or we separate out moving and drawing (or
		// queue the drawing) and also accept that we won't know the exact
		// placement of the screen until quite late (which makes pixels perfect
		// Alien freezing and defrosting impossible). That's a big voyage into
		// new territory for little gain.
		//
		// For now, it'll work how it used to. For the first time I can say "I
		// am clear about the limits this imposes".
		//

		updateScore();

	}

	public void addAlien(Alien alien) {
		List<Alien> target = alien.infront ? foregroundAlienList : backgroundAlienList;
		target.add(alien);
	}

	private void updateScore() {
		if (score!=oldScore) {
			scoreHeadingText = font.preDraw(0xffffff00, 0, "score");
			scoreText = font.preDraw(0xffffffff, 0, String.format("%08d", score));
		}
		scoreHeadingText.draw((Main.SCREEN_WIDTH - scoreHeadingText.getWidth()) / 2, 6);
		scoreText.draw((Main.SCREEN_WIDTH - scoreText.getWidth()) / 2, 6+14);
	}

	private void updateAliens(List<Alien> al, Box screenBox) {
		for (Iterator<Alien> alienIterator = al.iterator(); alienIterator.hasNext();) {
			Alien alien = alienIterator.next();
			alien.freezeBounds = null;
			alien.update();
			if (alien.remove) {
				alienIterator.remove();
			}
			else {
				perhapsFreezeOne(alien, alienIterator, screenBox);
			}
		}
	}

	// ---------------------------------------------------------------------------
	// REFRIGERATION
	
	private boolean perhapsFreezeOne(Alien alien, Iterator<Alien> alienIterator, Box screenBox) {
		Box fb = alien.freezeBounds;
		if (fb == null) {
			return false;
		}
		if (fb.right < screenBox.left) {
			freezeOne(alien, alienIterator, freezeLeft, -fb.right);
		}
		else if (fb.bottom < screenBox.top) {
			freezeOne(alien, alienIterator, freezeTop, -fb.bottom);
		}
		else if (fb.left > screenBox.right) {
			freezeOne(alien, alienIterator, freezeRight, fb.left);
		}
		else if (fb.top > screenBox.bottom) {
			freezeOne(alien, alienIterator, freezeBottom, fb.top);
		}
		else {
			return false;
		}
		return true;
	}

	private void freezeOne(Alien alien, Iterator<Alien> alienIterator, Fridge<Alien> fridge, int restore) {
		alienIterator.remove();
		fridge.add(alien, restore);
	}
		
	private void defrostAny(Box screenBox) {
		defrostAnyFrom(freezeLeft, -screenBox.left);
		defrostAnyFrom(freezeTop, -screenBox.top);
		defrostAnyFrom(freezeRight, screenBox.right);
		defrostAnyFrom(freezeBottom, screenBox.bottom);
	}

	private void defrostAnyFrom(Fridge<Alien> fridge, int restore) {
		for (;;) {
			Alien a = fridge.remove(restore);
			if (a==null) break;
			addAlien(a);
		}
	}

}
