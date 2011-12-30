package com.nney.tt.aliens;

import com.nney.tt.props.PropAnn;
import com.nney.tt.sprites.Anim;
import com.nney.tt.sprites.Sprite;
import com.nney.utils.Math2;

public class SpikeAlien extends AlienWithLocation {
	private Anim ourAnim;

	@PropAnn(doc = "Our movement in relation to other spikes (0-99)", max = 99)
	public int phase;

	@PropAnn(doc = "Our poking out frequency (20-1000)", min = 20, max = 1000)
	public int frequency = 100;

	@Override
	public void onLoaded() {
		ourAnim = anims.find(0);
	}

	@Override
	public void update() {
		freezeBounds = ourAnim.getBounds().add2(c);

		int f = srv.getFrameNumber() + Math2.percent(frequency, phase);
		f %= frequency;

		Sprite s = ourAnim.randomAccessByFrameNumber(f);
		if (s != null) {
			srv.drawSprite(c, s);
			if (srv.collideAlienWithPlayerHiRes(c, s)) {
				srv.getThePlayer().stun();
			}
		}
	}
}
