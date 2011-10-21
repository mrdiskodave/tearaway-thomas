package com.nney.tt.aliens;

import com.nney.tt.props.PropAnn;
import com.nney.utils.Math2;

public abstract class AppearingAlien extends AlienWithLocation {
	@PropAnn(name = "Hidden", doc = "Will we suddenly appear when the player runs past?", label = "hidden")
	public boolean hidden;

	private boolean falling;
	private int fallSpeed;

	@Override
	public void loadFromLegacyData() {
		hidden = Math2.bitTest(loadByte(OBflags), OBFinvis);
	}

	@Override
	public void onLoaded() {
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
				// reveal?
				if (reveal) {
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
