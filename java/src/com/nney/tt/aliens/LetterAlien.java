package com.nney.tt.aliens;

import com.nney.tt.TearawayLetters;
import com.nney.tt.props.PropAnn;
import com.nney.tt.sprites.Sprite;
import com.nney.utils.Math2;

/**
 * One of the letters of TEARAWAY in the final challenge (l_alien in s195). The
 * one you need next is lit; the others are dim. Collect the right one and the
 * clock goes back to 60 seconds. The last one finishes the stage.
 */
public class LetterAlien extends AlienWithLocation {
	private static final int FIRST_TYPE = 105;

	@PropAnn(doc = "For the A's: which one this is (2, 4 or 6), for the advice screens")
	public int slot = 6;

	private static final int OBFbehind = 6;
	private static final int OBFclimb = 3;

	@Override
	public void loadFromLegacyData() {
		int flags = loadByte(OBflags);
		slot = Math2.bitTest(flags, OBFclimb) ? 2 : Math2.bitTest(flags, OBFbehind) ? 4 : 6;
	}

	private int letter() {
		return alienInfo.typeCode - FIRST_TYPE;
	}

	@Override
	public void update() {
		TearawayLetters letters = srv.getLetters();
		boolean wanted = letters.isWanted(letter());
		Sprite s = anims.find(letter() * 2 + (wanted ? 0 : 1)).firstSprite();
		srv.drawSprite(c, s);
		freezeBounds = spriteBounds(s);

		if (wanted && playerInOriginalBox(c, 149, 139, 169, 118)) {
			letters.collect(letter(), slot);
			srv.setTimeRemaining(60);
			srv.playSoundEffect("gem");
			done();
			if (letters.isComplete()) {
				srv.awardExtraLife();
				srv.levelCompleted(null);
			}
		}
	}
}
