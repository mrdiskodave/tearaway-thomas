package com.nney.tt.aliens;

import com.nney.tt.geom.Coord;
import com.nney.tt.props.PropAnn;
import com.nney.tt.sprites.Anims;
import com.nney.tt.sprites.Sprite;
import com.nney.tt.tinytools.Countdown;
import com.nney.utils.Math2;

public class TankAlien extends LeftRightAlien {
	private static final int TURRET_POSITIONS = 8;

	private static final int FLAG_CAN_MOVE = 3;

	@PropAnn(doc = "Are we able to move?")
	public boolean canMove;

	private Countdown stunTimer = new Countdown();
	private Countdown fireTimer = new Countdown();
	private int currentTurretAngle;

	@Override
	public void loadFromLegacyData() {
		super.loadFromLegacyData();
		System.out.println(String.format("Tank flag %02x", loadByte(OBflags)));
		canMove = !Math2.bitTest(loadByte(OBflags), FLAG_CAN_MOVE);
		
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
		if (srv.frameTest(2)) {
			if (stunTimer.testAndRun()) {
				currentTurretAngle += 1;
				currentTurretAngle %= TURRET_POSITIONS;
				if (!stunTimer.test()) {
					reloadFireTimer();
				}
			}
			else {
				boolean faceLeft = srv.getPlayerPosition().x < c.x;
				int desiredTargetAngle = faceLeft ? 4 : 0;
				// System.out.println("Target:"+target);
				if (currentTurretAngle == desiredTargetAngle) {
					if (!fireTimer.testAndRun()) {
						reloadFireTimer();
						int sign = faceLeft ? -1 : 1;
						Coord shellVelocity = new Coord(sign*4, 0);
						Coord shellStart = c.copyAndAdd(sign*28, -20);
						srv.addAlien(new ShellAlien(shellStart, shellVelocity));
					}
				}
				else {
					currentTurretAngle += TURRET_POSITIONS;
					currentTurretAngle = Math2.closer(currentTurretAngle, desiredTargetAngle, 1);
					currentTurretAngle %= TURRET_POSITIONS;
				}
			}
		}
		
		Sprite sprite = nextFrame();
		srv.drawSprite(c, sprite);
		
		Sprite turretSprite = anims.find("turret").sprites[currentTurretAngle];
		srv.drawSprite(c, turretSprite);

		if (srv.collideAlienWithPlayerHiRes(c, sprite) || srv.collideAlienWithPlayerHiRes(c, turretSprite)) {
			if (srv.headBounce(this, turretSprite, sprite)) {
				stunTimer.set(60);
			}
		}
	}

	private void reloadFireTimer() {
		fireTimer.set(srv.randomness(32) + 50);
	}

}
