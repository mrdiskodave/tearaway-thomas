package com.nney.tt;

import junit.framework.TestCase;

public class JumpHeightTest extends TestCase {
	public void testMain() throws Exception {
		float initialVelocity = 12.245f;
		System.out.println(computeJumpHeight(initialVelocity));
	}

	float computeJumpHeight(float v) {
		float h = 0;
		int ih = 0;
		float yfrac = 0;
		for (;;) {
			v--;
			if (v<=0) break;
			
			h += v;
			
			yfrac = yfrac + v;
			int moveBy = (int) yfrac;
			yfrac -= moveBy;

			ih += moveBy;
			
			System.out.println(String.format("v=%s h=%s ih=%s frac=%s", v, h, ih, yfrac));
		}
		return h;
	}
}
