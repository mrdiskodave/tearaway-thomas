package com.nney.tt;

import java.util.Random;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.map.BlockSpecifications;
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


	/**
	 * Is a key pressed.
	 * 
	 * @param key
	 *            The key the caller is asking about.
	 * @return <code>true</code> meaning "it is" or <code>false</code> meaning
	 *         "it is not".
	 */
	boolean testKey(int key);

	/**
	 * What is there?
	 * 
	 * @param where
	 *            The pixel location being queried.
	 * @return The kind of block that is there. e.g. "magic" or "ladder" or any
	 *         text string used in the configuration of a
	 *         {@link BlockSpecifications} object.
	 */
	String getBlockSpecification(Coord where);

	Coord getPlayerPosition();

	void validatePlayerPosition(Coord c);

	int getFrameNumber();

	void scrollTowards(Coord c);

	void queueSprite(Coord c, Sprite s);

	void queueDebugText(Coord c, String text);

	void registerPlayerSpriteForAlienColisions(Coord c, Sprite s);

	boolean collideAlienDeluxePaintBoxWithPlayer(Coord alienPos, Box deluxePaintBox);

	boolean collideAlienWithPlayerHiRes(Coord alienPos, Sprite alienSprite);

	boolean collideAlienWithPlayerBounds(Coord alienPos, Sprite alienSprite);

	void stunThePlayer();


	
	boolean landingSite(Coord c);
	
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
	 *         above the ground) or <code>false</code> meaning "no" (we fell more
	 *         than fallMax and didn't touch ground so have not changed the
	 *         given {@link Coord}).
	 */
	boolean playerFall(Coord where, int fallMax);


}