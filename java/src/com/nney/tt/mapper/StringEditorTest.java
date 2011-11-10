package com.nney.tt.mapper;

import junit.framework.TestCase;

public class StringEditorTest extends TestCase {
	private StringEditor se;

	public void testScrolling() {
		se = new StringEditor("f", 12, 3, null);
		
		for (int x=0; x<26; x++) {
			char c = (char)('a'+x);
			System.out.println("Type:"+c);
			se.opType(c);
		}
		System.out.println(se.state());
		
	}
	
	public void bestOps() throws Exception {
//		KeyMap smk = new KeyMap() {
//			@Override
//			public int mapKey(int key) {
//				if (key>=Keyboard.KEY_0 && key<=Keyboard.KEY_9) {
//					key -= Keyboard.KEY_0;
//					key += '0';
//					return key;
//				}
//				return -1;
//			}
//		};
		se = new StringEditor("f", 1000, 1000, null);
		expect("f_");
		se.opDeleteToStart();
		se.opType('0');
		expect("0_");
		se.opType('1');
		expect("01_");
		se.opRight();
		expect("01_!");
		se.opLeft();
		expect("0_1");
		se.opLeft();
		expect("_01");
		se.opLeft();
		expect("_01!");
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
		se.opDeleteBack();
		expect("_12!");
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
		se.opDeleteHere();
		expect("_!");
		se.opDeleteBack();
		expect("_!");
	}

	public void send(int z) {
		se.keyIn(z);
	}

	private void expect(String expect) {
		String actual = se.state().toString();
		assertEquals(expect, actual);
	}

}
