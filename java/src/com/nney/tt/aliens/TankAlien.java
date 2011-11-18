package com.nney.tt.aliens;

import org.lwjgl.util.glu.Project;

import com.nney.tt.geom.Coord;
import com.nney.tt.props.PropAnn;
import com.nney.tt.sprites.Anims;
import com.nney.tt.sprites.Sprite;
import com.nney.tt.tinytools.Countdown;
import com.nney.utils.Math2;

public class TankAlien extends LeftRightAlien {
	private static final int FLAG_CAN_MOVE = 3;

	@PropAnn(doc = "Are we able to move?")
	public boolean canMove;

	private Countdown stunTimer = new Countdown();
	private Countdown fireTimer = new Countdown();
	private int currentTurretAngle;

	@Override
	public void loadFromLegacyData() {
		super.loadFromLegacyData();
		canMove = Math2.bitTest(loadByte(OBflags), FLAG_CAN_MOVE);
	}

	@Override
	public void onPropUpdate() {
		setAnimation(Anims.directionalAnimName(goLeft, ""));
		if (!canMove) animPlayer.customiseRate(0);
	}

	@Override
	public void update() {
		if (canMove) {
			moveLeftRight(1);
		}
		Coord canFire = null;
		if (srv.frameTest(2)) {
			if (stunTimer.run().test()) {
				currentTurretAngle += 1;
				currentTurretAngle %= 8;
			}
			else {
				boolean faceLeft = srv.getPlayerPosition().x < c.x;
				int desiredTargetAngle = faceLeft ? 4 : 0;
				// System.out.println("Target:"+target);
				if (currentTurretAngle == desiredTargetAngle) {
					if (!fireTimer.run().test()) {
						reloadFireTimer();
						System.out.println("Bang!");
						int m = faceLeft ? -1 : 1;
						Coord sv = new Coord(m*4, 0);
						Coord sd = new Coord(m*28, -20);
						srv.addAlien(new ShellAlien(c.add2(sd), sv));
					}
				}
				else {
					currentTurretAngle += 8;
					currentTurretAngle = Math2.closer(currentTurretAngle, desiredTargetAngle, 1);
					currentTurretAngle %= 8;
				}
			}
		}
		Sprite s = nextFrame();
		srv.drawSprite(c, s);
		Sprite ts = anims.find("turret").sprites[currentTurretAngle];
		srv.drawSprite(c, ts);

		// if (srv.collideAlienWithPlayerHiRes(c, s)) {
		// srv.headBounce(this, s);
		// }
	}

	private void reloadFireTimer() {
		fireTimer.set(srv.randomness(32) + 50);
	}

}
