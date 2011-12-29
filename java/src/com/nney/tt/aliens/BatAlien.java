package com.nney.tt.aliens;

public class BatAlien extends BumbleAlien {
	@Override
	public void nextDestination() {
		d.x += srv.randomness(129) - 64;
		d.y += srv.randomness(129) - 64;
		box.constrain(d);
	}
}
