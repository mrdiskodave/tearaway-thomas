package com.nney.tt.osd;

import junit.framework.TestCase;

public class OsdParserTest extends TestCase {
	public void test1() throws Exception {
		String send = "hello[n][k7]bye[k]cheese[c1]";
		String expect = "text:hello,cr,kern:7,text:bye,kern:0,text:cheese,col:1";
		assertItWorks(send, expect);
	}

	public void test2() throws Exception {
		String send = "hello[p][k7]b[c2]ell[c1]y[n][p][k]cheese";
		String expect = "text:hello,para,kern:7,text:b,col:2,text:ell,col:1,text:y,cr,para,kern:0,text:cheese";
		assertItWorks(send, expect);
	}

	public void test3() throws Exception {
		String send = "hello[t3,7][e][e]";
		String expect = "text:hello,table:3,7,endCell,endCell";
		assertItWorks(send, expect);
	}

	private void assertItWorks(String send, String expect) {
		MockTextDest td = new MockTextDest(); 
		OsdParser p = new OsdParser(td);
		p.parse(send);
		String actual = td.toString();
		System.out.println(expect);
		System.out.println(actual);
		System.out.println();
		assertEquals(expect, actual);
	}
}
