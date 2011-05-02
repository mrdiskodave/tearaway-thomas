package com.nney.tt.aliens;

import com.nney.tt.BitOp;

public abstract class BonusAlien extends Alien {
	private static final int FLAG_INVIS = 5;
	private boolean invis;
	private boolean falling;
	private int fallSpeed;

	@Override
	public void load() {
		invis = BitOp.test(loadByte(OBflags), FLAG_INVIS);
	}
	
	@Override
	public void init() {
		changeAnimation(0);
	}
	
	@Override
	public void update() {
		if (!invis) {
			normalUpdate();
		}
		else {
			if (falling) {
				if (srv.fall(c, fallSpeed)) {
					falling = false;
					invis = false;
					normalUpdate();
				}
				else {
					if (fallSpeed<6 && srv.frameTest(1, 1)) {
						fallSpeed++;
					}
					justDraw();
				}
			}
			else {
				if (srv.getThePlayer().checkUnhide(c)) {
					falling = true;
				}
				else {
					if (srv.frameTest(31, 16)) {
						justDraw();
					}
				}
			}
		}
	}

	abstract protected void justDraw();
	
	abstract protected void normalUpdate();
}
