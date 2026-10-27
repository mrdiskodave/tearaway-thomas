package com.nney.tt.aliens;

import com.nney.tt.geom.XRange;
import com.nney.tt.props.PropAnn;
import com.nney.tt.sprites.Sprite;

/**
 * The worm in "the worm that turned" (worm_alien in s195). It inches back and
 * forth; walk over it and you squash it, which is that level's secret: the
 * next bonus "fruit 'em up" stage is played.
 * 
 * It only moves as its animation moves on, by the amount in worm_table for
 * the frame it's leaving, so it really does inch along.
 */
public class WormAlien extends AlienWithLocation {
	private static final int[] STEP = { 0, 0, 0, 0, 0, 0, 1, 1, 1 };
	private static final int SQUASHED = 2;

	@PropAnn(doc = "The span we wriggle across.", label = "range")
	public XRange range;

	@PropAnn(doc = "Heading right?")
	public boolean right;

	private boolean squashed;

	@Override
	public void resetTo(com.nney.tt.geom.Coord p) {
		super.resetTo(p);
		range = new XRange(p.x - 30, p.x + 30);
	}

	@Override
	public void loadFromLegacyData() {
		range = new XRange((short) loadShort(OBleft), (short) loadShort(OBright));
		right = (loadByte(OBstatus0) & 1) != 0;
	}

	@Override
	public void update() {
		if (squashed) {
			Sprite s = anims.find(SQUASHED).firstSprite();
			srv.drawSprite(c, s);
			freezeBounds = spriteBounds(s);
			return;
		}

		// the original drew animation number OBstatus0 (0 or 1)
		changeAnimation(right ? 1 : 0);
		int before = animPlayer.position();
		Sprite s = nextFrame();
		if (animPlayer.position() != before) {
			int step = STEP[Math.min(before, STEP.length - 1)];
			if (right) {
				c.x += step;
				if (c.x > range.right) right = false;
			}
			else {
				c.x -= step;
				if (c.x < range.left) right = true;
			}
		}
		srv.drawSprite(c, s);
		freezeBounds = spriteBounds(s);

		if (srv.getThePlayer().isOnTheGround() && playerInOriginalBox(c, 156, 131, 165, 128)) {
			squashed = true;
			srv.secretBonusFound();
			srv.playSoundEffect("worm");
		}
	}
}
