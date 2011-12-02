package com.nney.utils;

import java.util.Arrays;

import junit.framework.TestCase;

public class ListUtilAndPyUtilTest extends TestCase {
	public void testBackwards() throws Exception {
		assertListMatches("7,6,4", ListUtil.reversed(Arrays.asList(4, 6, 7)));
	}

	public void testRange() throws Exception {
		assertListMatches("0,1,2,3,4", PyUtil.range(5));
		assertListMatches("4,3,2,1,0", PyUtil.reversedRange(5));

		// examples from
		// http://docs.python.org/library/functions.html#range
		assertListMatches("0,1,2,3,4,5,6,7,8,9", PyUtil.range(10));
		assertListMatches("1,2,3,4,5,6,7,8,9,10", PyUtil.range(1, 11));
		assertListMatches("0,5,10,15,20,25", PyUtil.range(0, 30, 5));
		assertListMatches("0,3,6,9", PyUtil.range(0, 10, 3));
		assertListMatches("0,-1,-2,-3,-4,-5,-6,-7,-8,-9", PyUtil.range(0, -10, -1));
		assertListMatches("", PyUtil.range(0));
		assertListMatches("", PyUtil.range(1, 0));
	}

	public void assertListMatches(String expect, Iterable<Integer> actual) {
		assertEquals(expect, ListUtil.toString(actual));
	}
}
