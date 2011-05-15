package com.nney.tt.aliens;

import com.nney.tt.BitOp;

public abstract class HiddenAlien extends Alien {
	private static final boolean CTC_FLASH_HIDDEN = false;

	private static final int FLAG_INVIS = 5;
	
	@AlienProp(name="Invisible", doc="Will we suddenly appear when the player runs past?")
	public boolean invis;
	
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
					if (fallSpeed < 6 && srv.frameTest(2, 1)) {
						fallSpeed++;
					}
					normalUpdate();
				}
			}
			else {
				// we're hidden
				if (CTC_FLASH_HIDDEN) {
					if (srv.frameTest(32, 16)) {
						normalUpdate();
					}
				}
				// reveal?
				if (srv.getThePlayer().checkReveal(c)) {
					// yes - reveal!
					falling = true;
				}
			}
		}
		else {
			normalUpdate();
		}
	}

	abstract protected void normalUpdate();
	
	protected boolean isFalling() {
		return falling;
	}
}
