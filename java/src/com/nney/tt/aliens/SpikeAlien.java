package com.nney.tt.aliens;

import com.nney.tt.sprites.Anim;
import com.nney.tt.sprites.Sprite;

public class SpikeAlien extends AlienWithLocation {
	private int freq = 100;
	private Anim ourAnim;

	@AlienProp(name = "Phase", doc = "Our movement in relation to other spikes", label = "phase")
	public int phase;
	
	@Override
	public void onLoaded() {
		ourAnim = anims.find(0);
	}
	
	@Override
	public void update() {
		freezeBounds = ourAnim.box().add2(c);

		int f = srv.getFrameNumber() + phase;
		f %= freq;

		Sprite s = ourAnim.randomAccessByFrameNumber(f);
		if (s!=null) {
			srv.drawSprite(c, s);
			if (srv.collideAlienWithPlayerHiRes(c, s)) {
				srv.getThePlayer().stun();
			}
		}
	}
}
