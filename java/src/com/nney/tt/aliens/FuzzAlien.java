package com.nney.tt.aliens;

import com.nney.tt.Const;
import com.nney.tt.sprites.Sprite;

/**
 * A fuzzy screen (fuzz_alien in s195). Jump into it and it clears to show
 * something:
 * 
 * <ul>
 * <li>In the final challenge, an arrow pointing the way to the next letter,
 * for 250 frames, then it goes fuzzy again.</li>
 * <li>Anywhere else it's a level's secret: it shows "bonus" and the next fruit
 * stage will be played.</li>
 * </ul>
 */
public class FuzzAlien extends AlienWithLocation {
	private static final int ARROW_TIME = 250;
	/** Anims: fuzz, ready4arrow, up, right, down, left, bonus. */
	private static final int CLEARING = 1;
	private static final int FIRST_ARROW = 2;
	private static final int BONUS = 6;

	private enum State {
		FUZZ, CLEARING, SHOWING
	}

	private State state = State.FUZZ;
	private int showing;
	private int timer;
	private int clearingFrames;

	@Override
	public void onLoaded() {
		changeAnimation(0);
	}

	@Override
	public void update() {
		Sprite s;
		switch (state) {
		case FUZZ:
			s = nextFrame();
			// jumped into, not just walked past
			if (playerInOriginalBox(c, 165, 105, 182, 58) && !srv.getThePlayer().isOnTheGround()) {
				state = State.CLEARING;
				changeAnimation(CLEARING);
				clearingFrames = anims.find(CLEARING).lengthInFrames();
			}
			break;
		case CLEARING:
			s = nextFrame();
			if (--clearingFrames <= 0) show();
			break;
		default:
			s = anims.find(showing).firstSprite();
			if (srv.isChallenge() && --timer < 0) {
				state = State.FUZZ;
				changeAnimation(0);
			}
			break;
		}
		srv.drawSprite(c, s);
		freezeBounds = spriteBounds(s);
	}

	private void show() {
		if (!srv.isChallenge()) {
			srv.secretBonusFound();
			srv.playSoundEffect("gem");
			showing = BONUS;
			state = State.SHOWING;
			return;
		}
		int dir = srv.getLetters().hint(c.x >> Const.BLOCK_SHIFT, c.y >> Const.BLOCK_SHIFT);
		if (dir < 0) {
			state = State.FUZZ;
			changeAnimation(0);
			return;
		}
		showing = FIRST_ARROW + dir;
		timer = ARROW_TIME;
		state = State.SHOWING;
	}
}
