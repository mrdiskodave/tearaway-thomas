package com.nney.tt.aliens;

import com.nney.utils.Math2;

public class Wave {
	static class Result {
		public final int pos;
		public final int dir;

		Result(int pos, int dir) {
			this.pos = pos;
			this.dir = dir;
		}
		
		@Override
		public String toString() {
			if (dir>0) return ">"+pos;
			if (dir<0) return "<"+pos;
			return "="+pos;
		}
		
		public boolean goLeft() {
			return dir<0;
		}
	}
	
	final public static Result sawToothWaveWithPause(int x, int max, int pause) {
		int cycleLength = sawToothWaveWithPauseCycleLength(max, pause);
		x %= cycleLength;
		if (x<pause) {
			return new Result(0, 0);
		}
		x-=pause;
		if (x<max) {
			return new Result(x, 1);
		}
		x-=max;
		if (x<pause) {
			return new Result(max, 0);
		}
		x-=pause;
		return new Result(max-x, -1);
	}

	public final static int sawToothWaveWithPauseCycleLength(int max, int pause) {
		return 2*(max + pause);
	}

	public final static Result sawToothWaveWithPauseAndPhase(int span, int pause, int phase, int frm) {
		int len = Wave.sawToothWaveWithPauseCycleLength(span, pause);
		int fphase = Math2.percent(len, phase);
		return Wave.sawToothWaveWithPause(frm+fphase, span, pause);
	}

	public final static Result z(int span, int pause, int phase, int frm) {
		return Wave.sawToothWaveWithPause(frm+phase, span, pause);
	}

}
