package com.nney.tt.aliens;

public class Wave {
	final public static int sawToothWaveWithPause(int x, int max, int pause) {
		int cycleLength = sawToothWaveWithPauseCycleLength(max, pause);
		x %= cycleLength;
		if (x<pause) {
			return 0;
		}
		x-=pause;
		if (x<max) {
			return x;
		}
		x-=max;
		if (x<=pause) {
			return max;
		}
		x-=pause;
		return max-x;
	}

	public final static int sawToothWaveWithPauseCycleLength(int max, int pause) {
		return 2*(max + pause);
	}

}
