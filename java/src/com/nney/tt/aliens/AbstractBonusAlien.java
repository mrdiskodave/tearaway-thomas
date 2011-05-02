package com.nney.tt.aliens;

import com.nney.tt.BitOp;

public abstract class AbstractBonusAlien extends Alien {
	private static final boolean CTC_FLASH_HIDDEN = false;
	
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
		if (invis) {
			if (falling) {
				if (srv.fall(c, fallSpeed)) {
					// we hit the ground
					falling = false;
					invis = false;
					normalUpdate();
				}
				else {
					// apply gravity and continue falling
					if (fallSpeed<6 && srv.frameTest(2, 1)) {
						fallSpeed++;
					}
					stationaryUpdate();
				}
			}
			else {
				// we're hidden
				if (CTC_FLASH_HIDDEN) {
					if (srv.frameTest(32, 16)) {
						stationaryUpdate();
					}
				}
				// unhide?
				if (srv.getThePlayer().checkUnhide(c)) {
					falling = true;
				}
			}
		}
		else {
			normalUpdate();
		}
	}

	abstract protected void stationaryUpdate();
		
	protected void normalUpdate() {
		stationaryUpdate();
	}
}
