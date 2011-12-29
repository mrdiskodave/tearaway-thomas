package com.nney.tt.mapper;

import junit.framework.TestCase;

public class StringEditorTest extends TestCase {
	private StringEditor se;

	public void testScrolling() {
		se = new StringEditor("", 12);

		for (int x = 0; x < 26; x++) {
			char c = (char) ('a' + x);
			System.out.println("Type:" + c);
			se.opType(c);
		}
		expect("pqrstuvwxyz_");
		se.opBegin();
		expect("_abcdefghijkl");
		se.opRight();
		se.opRight();
		se.opRight();
		se.opRight();
		se.opRight();
		se.opRight();
		se.opRight();
		se.opRight();
		se.opRight();
		se.opRight();
		se.opRight();
		expect("abcdefghijk_l");
		se.opDeleteHere();
		expect("abcdefghijk_m");
	}

	public void bestOps() throws Exception {
		se = new StringEditor("f", 1000);
		expect("f_");
		se.opDeleteToStart();
		se.opType('0');
		expect("0_");
		se.opType('1');
		expect("01_");
		se.opRight(); // illegal action
		expect("01_");
		se.opLeft();
		expect("0_1");
		se.opLeft();
		expect("_01");
		se.opLeft(); // illegal action
		expect("_01");
		se.opEnd();
		expect("01_");
		se.opEnd();
		expect("01_");
		se.opType('2');
		expect("012_");
		se.opBegin();
		expect("_012");
		se.opType('7');
		expect("7_012");
		se.opDeleteHere();
		expect("7_12");
		se.opDeleteBack();
		expect("_12");
		se.opDeleteBack(); // illegal action
		expect("_12");
		se.opRight();
		se.opDeleteToEnd();
		expect("1_");
		se.opDeleteToEnd();
		expect("1_");
		se.opType('2');
		se.opType('3');
		se.opLeft();
		se.opDeleteToStart();
		expect("_3");
		se.opDeleteToStart();
		expect("_3");
		se.opDeleteToEnd();
		expect("_");
		se.opDeleteHere(); // illegal action
		expect("_");
		se.opDeleteBack(); // illegal action
		expect("_");
	}

	private void expect(String expect) {
		String actual = se.state().toString();
		assertEquals(expect, actual);
	}

}
