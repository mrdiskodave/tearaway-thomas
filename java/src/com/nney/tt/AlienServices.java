package com.nney.tt;

import java.util.Random;

import com.nney.tt.aliens.Alien;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Sprite;

public interface AlienServices {

	/**
	 * Get some randomness.
	 * 
	 * @param n
	 *            Exactly like the parameter given to
	 *            {@link Random#nextInt(int)}.
	 * @return
	 */
	int randomness(int n);

	int getFrameNumber();
	
	int getChangingNumber();

	boolean frameTest(int mask, int lessThan);

	void drawSprite(Coord c, Sprite s);

	void drawSprite(Coord c, Sprite s, boolean drawWhite);

	boolean collideAlienWithPlayerHiRes(Coord alienPos, Sprite alienSprite);

	boolean inTheGround(Coord c);

	/**
	 * Interact with the ground.
	 * 
	 * @param where
	 *            Where we're at.
	 * @param fallMax
	 *            The called-defined limit on falling (in pixels).
	 * @return Success? <code>true</code> meaning "yes" (we were in the ground
	 *         and floated up a bit <b>or</b> we fell by 0-<code>fallMax</code>
	 *         pixels but, either way, we are now resting exactly one pixel
	 *         above the ground) or <code>false</code> meaning "no" (we fell
	 *         more than fallMax and didn't touch ground so have not changed the
	 *         given {@link Coord}).
	 */
	boolean playerFall(Coord where, int fallMax);

	// called by the player
	void validatePlayerPosition(Coord c);

	void registerPlayerSpriteForAlienColisions(Coord c, Sprite s);

	// called by Aliens to operate on the player

	Coord getPlayerPosition();

	Player getThePlayer();

	boolean blockInfoIs(Coord c, String name);

	String blockInfoHas(Coord c, String prefix);

	LadderInformation getLadderInfo();

	boolean fall(Coord c, int fallSpeed);

	/**
	 * Give a score to the player (and a notice of that score on screen).
	 * 
	 * @param score
	 *            Score to give.
	 * @param noticeLocation
	 *            Coordinates for the notice (or <code>null</code> if you don't
	 *            want to display notice). Note that if you are displaying
	 *            notice then the score may only be 1, 50, 100, 200, 300, 400,
	 *            500, 600, 700, 800, 900, 1000, 2500 and 5000 as that is all
	 *            that we have notice-graphics for!
	 */
	void awardScore(int score, Coord noticeLocation);

	void magicDust(Coord where);

	/**
	 * Like {@link #awardScore(int, Coord)} but for gems. Also decrements the
	 * remaining gem counter and doubles the score if the exit is already open.
	 */
	void oneLessGem(int score, Coord notice);

	boolean isExitOpen();

	boolean collideBoxWithPlayer(Box box);

	void teleportTo(Coord destination);

	void drawDebugText(Coord c, String text);

	void applyMapEdits(Coord c, int[][] mapEdits);

	boolean collideBoxWithPlayerHandle(Box box);

	void awardExtraTime(int seconds);

	void awardExtraLife();

	void headBounce(Alien alien, Sprite alienSprite);

	boolean isOffTheBottom(Coord c);

	void levelCompleted(Coord exit);

	boolean showText();

	void playSoundEffect(String name);

}