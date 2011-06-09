package com.nney.tt.aliens;

import junit.framework.TestCase;

public class SineTableTest extends TestCase {
	public void test() throws Exception {
		SineTable s = new SineTable(64, 16);
		int answer[] = {
				0,1,3,4,6,7,8,10,
				11,12,13,14,14,15,15,15,
				16,15,15,15,14,14,13,12,
				11,10,8,7,6,4,3,1,
				0,-1,-3,-4,-6,-7,-8,-10,
				-11,-12,-13,-14,-14,-15,-15,-15,
				-16,-15,-15,-15,-14,-14,-13,-12,
				-11,-10,-8,-7,-6,-4,-3,-1
		};
		for (int x=0; x<64; x++) {
			assertEquals(answer[x], s.get(x));
		}
	}
}
