package com.nney.coroutines;

import junit.framework.TestCase;

public class CoroutineTest extends TestCase {
	public void test() throws Exception {
		final StringBuffer sb = new StringBuffer();
		
		Coroutine co = new Coroutine("NameOfTheThreadThatItRunsIn") {
			@Override
			public void run() {
				for (int x = 0; x < 5; x++) {
					sb.append("x"+x);
					pause();
				}
			};
		};

		try {
			for (int y = 0; y < 99; y++) {
				sb.append("y"+y);
				co.step();
			}
			fail();
		}
		catch (CoTerminated ex) {
			// expected
		}
		
		String expect = "y0x0y1x1y2x2y3x3y4x4y5";
		String got = sb.toString();
		assertEquals(expect, got);
	}
}
