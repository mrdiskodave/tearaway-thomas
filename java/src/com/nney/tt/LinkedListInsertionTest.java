package com.nney.tt;

import java.util.LinkedList;
import java.util.ListIterator;
import java.util.Random;

import com.nney.utils.ListUtil;

import junit.framework.TestCase;

public class LinkedListInsertionTest extends TestCase {
	LinkedList<Integer> fixture = new LinkedList<Integer>();

	void insert(Integer x) {
		ListIterator<Integer> fi = fixture.listIterator();
		while (fi.hasNext()) {
			if (fi.next() >= x) {
				fi.previous();
				break;
			}
		}
		fi.add(x);
	}

	public void test() throws Exception {
		Random repeatableData = new Random(5);
		for (int x = 0; x < 70; x++) {
			insert(repeatableData.nextInt(5));
		}

		String actual = ListUtil.toString(fixture, "");
		assertEquals("0000000000000001111111111112222222222222222222233333333333334444444444", actual);
	}
}
