package com.nney.tt.map;

import java.util.Random;

import junit.framework.TestCase;

public class BitArrayTest extends TestCase {

	public void testMain() throws Exception {
		Random r = new Random(5);

		for (int length = 1; length < 1000; length++) {
			for (int testNumber = 0; testNumber < 30; testNumber++) {
				BitArray fixture = new BitArray(length);
				boolean[] expectations = new boolean[length];
				for (int indx = 0; indx < length; indx++) {
					boolean coinToss = r.nextBoolean();
					if (coinToss) {
						expectations[indx] = true;
						fixture.set(indx);
					}
				}
				for (int indx = 0; indx < length; indx++) {
					assertEquals(expectations[indx], fixture.test(indx));
				}
			}
		}
	}
}
