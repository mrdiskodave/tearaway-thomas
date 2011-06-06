package com.nney.tt.aliens;

import com.nney.tt.BitOp;

public abstract class AppearingAlien extends AlienWithLocation {
	@AlienProp(name = "Hidden", doc = "Will we suddenly appear when the player runs past?")
	public boolean hidden;

	private boolean falling;
	private int fallSpeed;

	private int fizzTimer;

	@Override
	public void loadFromLegacyData() {
		hidden = BitOp.test(loadByte(OBflags), OBFinvis);
	}

	@Override
	public void visualReset() {
		changeAnimation(0);
	}

	@Override
	public void update() {
		if (hidden) {
			if (falling) {
				if (srv.fall(c, fallSpeed)) {
					// we hit the ground
					falling = false;
					hidden = false;
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
				boolean reveal = srv.getThePlayer().checkReveal(c);
				
				if (srv.isMapping()) {
					boolean fizz = fizzTimer!=0;
					if (fizz) {
						fizzTimer--;
					}
					int freq = fizz ? 8 : 64;
					boolean show = srv.frameTest(freq, freq/2);
					if (show) {
						normalUpdate();
					}
					if (reveal) {
						fizzTimer = 32;
					}
				}
				else {
					// reveal?
					if (reveal) {
						// yes - reveal!
						falling = true;
					}
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
