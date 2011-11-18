package com.nney.tt.aliens;

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
	private int turretAngle;

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
		boolean canFire = false;
		if (canMove) {
			moveLeftRight(1);
			if (srv.frameTest(2)) {
				if (stunTimer.testAndDec()) {
					turretAngle += 1;
					turretAngle %= 8;
				}
				else {
					boolean faceLeft =  srv.getPlayerPosition().x < c.x;
					int target = faceLeft ? 4 : 0;
					System.out.println("Target:"+target);
					if (turretAngle==target) {
						canFire = true;
					}
					else {
						turretAngle += 8;
						turretAngle = Math2.closer(turretAngle, target, 1);
						turretAngle %= 8;
					}
				}
			}
		}
		if (canFire && fireTimer.testAndDec()) {
			reloadFireTimer();
			System.out.println("Bang!");
		}

		Sprite s = nextFrame();
		srv.drawSprite(c, s);
		Sprite ts = anims.find("turret").sprites[turretAngle];
		srv.drawSprite(c, ts);
		
//		if (srv.collideAlienWithPlayerHiRes(c, s)) {
//			srv.headBounce(this, s);
//		}
	}

	private void reloadFireTimer() {
		fireTimer.set(srv.randomness(32)+50);
	}

}
