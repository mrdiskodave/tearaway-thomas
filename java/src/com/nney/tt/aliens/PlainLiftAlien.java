package com.nney.tt.aliens;

import com.nney.tt.geom.Coord;

public class PlainLiftAlien extends LiftAlien {
	@AlienProp(name = "Start", label = "start")
	public Coord start;

	@AlienProp(name = "End", label = "end")
	public Coord end;

	@AlienProp(name = "Phase", doc = "Our movement in relation to other identical lifts (0-99)", label = "phase")
	private int phase;

	@AlienProp(name = "Pause", doc = "How long do we wait at either end?", label = "pause")
	private int pause;

	@Override
	public void resetTo(Coord c) {
		start = c.copyAndAdd(50, 0);
		end = c.copyAndAdd(-50, 0);
		phase = 0;
		pause = 50;
	}

	@Override
	protected Coord currentPosition() {
		Coord delta = end.sub2(start);
		Coord absDelta = new Coord(Math.abs(delta.x), Math.abs(delta.y));
		
		boolean majorX = absDelta.x>absDelta.y;
		int big = majorX ? absDelta.x : absDelta.y;
		
		int len = Wave.sawToothWaveWithPauseCycleLength(big, pause);
		int fphase = (phase*len)/100;
		// ^ those could be fields (assuming onPropChange() was called consistently)
		
		
		int pos = Wave.sawToothWaveWithPause(srv.getFrameNumber()+fphase, big, pause);

		float frac = pos;
		frac /= big;
		if (majorX) {
			delta.x = pos*Integer.signum(delta.x);
			delta.y = Math.round(delta.y*frac);
		}
		else {
			delta.x = Math.round(delta.x*frac);
			delta.y = pos*Integer.signum(delta.y);
		}
		
		delta.add(start);
		return delta;
	}
}
