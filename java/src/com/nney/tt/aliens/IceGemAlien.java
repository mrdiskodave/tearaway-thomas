package com.nney.tt.aliens;

import com.nney.tt.Player;
import com.nney.tt.geom.Coord;
import com.nney.tt.props.PropAnn;

/**
 * Iceland's block of ice (igem_alien in s195): you can stand on it, but land
 * on it too hard and it shatters and you drop through.
 * 
 * Each landing faster than 10 adds the excess to a damage count; once that
 * passes 2 it breaks. So a big drop breaks it at once, and a few medium ones
 * break it eventually. There's a gem frozen inside: when the ice has
 * shattered the gem is left behind (the original turned the object into a
 * yellow gem at x+2, y+17; our gems sit 8 further right).
 */
public class IceGemAlien extends LiftAlien {
	/** From the original's AGL table. */
	private static final int WIDTH = 18;
	private static final int SAFE_LANDING_SPEED = 10;
	private static final int TOUGHNESS = 2;

	@PropAnn(doc = "Where we are (top left)", label = "location")
	public Coord c = new Coord();

	private int damage;
	private boolean smashing;
	private int smashFrames;

	@Override
	public void resetTo(Coord p) {
		c = p.copy();
	}

	@Override
	public void onLoaded() {
		depth = DEPTH_LIFTS;
		lifts = new LiftImpl[] { new LiftImpl(firstFrame(), WIDTH) };
		setAnimation("out");
	}

	@Override
	protected Coord[] currentPosition() {
		// the lift code wants the middle
		return new Coord[] { c.copyAndAdd(WIDTH / 2, 0) };
	}

	@Override
	public void update() {
		LiftImpl lift = lifts[0];
		if (smashing) {
			srv.drawSprite(lift.liftNow, nextFrame());
			if (--smashFrames <= 0) {
				srv.addAlien("yellowGem", c.copyAndAdd(2 + 8, 17));
				done();
			}
			return;
		}

		Player p = srv.getThePlayer();
		if (!p.isOnTheGround() && p.wouldBoard(lift)) {
			int excess = (int) p.getVelocityY() - SAFE_LANDING_SPEED;
			if (excess > 0) {
				damage += excess;
				if (damage > TOUGHNESS) {
					smashing = true;
					changeAnimation("smashing");
					smashFrames = anims.find("smashing").lengthInFrames();
					srv.drawSprite(lift.liftNow, nextFrame());
					return;
				}
			}
		}
		super.update();
	}
}
