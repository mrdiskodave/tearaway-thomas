package com.nney.tt;

import java.util.Random;

import com.nney.tt.aliens.Alien;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.sprites.Sprite;

public interface AlienServices extends PlayerPositionServices {

	/**
	 * Get some randomness.
	 * 
	 * @param n
	 *            Exactly like the parameter given to
	 *            {@link Random#nextInt(int)}.
	 * @return
	 */
	int randomness(int n);

	/**
	 * Get current frame number. This is incremented once per frame during game
	 * play. It is not incremented at other times e.g. when paused or when using
	 * the Mapper.
	 * 
	 * @return
	 */
	int getFrameNumber();

	/**
	 * Is the frame number a multiple of the given value? e.g.
	 * <code>if (frameTest(2)) blah;</code> does blah every other frame.
	 * 
	 * @param m
	 *            The multiple. <b>must</b> be a power of two.
	 * @return <code>true</code> meaning "yes it is" or <code>false</code>
	 *         meaning "no it isn't".
	 */
	boolean frameTest(int m);

	void drawSprite(Coord c, Sprite s);

	void drawSprite(Coord c, Sprite s, boolean drawWhite);

	/**
	 * Draw a sprite partly see-through (the ghosts).
	 * 
	 * @param opacity
	 *            0 (invisible) to 1 (solid)
	 */
	void drawSpriteTranslucent(Coord c, Sprite s, float opacity);

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

	/**
	 * Can aliens touch the player just now? Not while he waits behind a text
	 * screen, or once the game is over.
	 */
	boolean playerTouchable();

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

	boolean isOffTheBottom(Coord c);

	void levelCompleted(Coord exit);

	boolean showText();

	void playSoundEffect(String name);

	void addAlien(Alien a);

	/**
	 * Make a new alien of a named type (as used in the level files) at the
	 * given place, e.g. the gem that falls out of a smashed block of ice.
	 */
	void addAlien(String name, Coord where);

	boolean keepInMap(Coord c);

	/**
	 * After having established a collision using
	 * {@link #collideAlienWithPlayerHiRes(Coord, Sprite)} call this method to
	 * check for head-bounces.
	 * 
	 * @param alien
	 *            The caller.
	 * @param alienSprites
	 *            The caller's sprites. Normally just one but there may be many
	 *            in special cases such as the tank with the independent turret.
	 *            If passing many the top-most should be passed in first (the
	 *            first one is used to place the head-bounce score-notification
	 *            above caller).
	 * @return Did a head-bounce happen? <code>true</code> meaning
	 *         "yes, it happened". Score is added, score notification is
	 *         displayed. If the caller has an animation named "fright" then
	 *         that will be used create a new FallingAlien in place of the
	 *         caller. This is the counted as a fatal head-bounce and will give
	 *         cumulative score if the player can keep doing them.
	 *         <code>false</code> meaning "no it didn't -- the player wasn't in
	 *         the right place so was stunned instead".
	 */
	boolean headBounce(Alien alien, Sprite... alienSprites);

	/**
	 * The player found a level's secret: the next bonus ("fruit 'em up") stage
	 * will be played rather than skipped.
	 */
	void secretBonusFound();

	/**
	 * The joystick as the player is using it this frame (see
	 * {@link com.nney.tt.input.Joystick}), e.g. for lifts the player drives.
	 */
	int getJoystick();

	/** The final challenge's letters (only meaningful on that stage). */
	TearawayLetters getLetters();

	/** Is this stage a challenge (rather than an ordinary or bonus stage)? */
	boolean isChallenge();

	/** Set the clock (the final challenge's letters put it back to 60). */
	void setTimeRemaining(int seconds);

	/** The map block at this point (the original's block numbers). */
	int getBlockNumber(Coord c);
}