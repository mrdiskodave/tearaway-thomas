package com.nney.tt.osd;

import com.nney.micromock.Mock;

import junit.framework.TestCase;

public class OsdParserTest extends TestCase {
	public void test1() throws Exception {
		Mock<TextDest> m = Mock.mock(TextDest.class);
		m.expect().addText("hello");
		m.expect().addCr();
		m.expect().setKern(7);
		m.expect().addText("bye");
		m.expect().setKern(0);
		m.expect().addText("cheese");
		m.expect().setCol(1);

		send("hello[n][k7]bye[k]cheese[c1]", m);
	}

	public void test2() throws Exception {
		Mock<TextDest> m = Mock.mock(TextDest.class);
		m.expect().addText("hello");
		m.expect().addParagraph();
		m.expect().setKern(7);
		m.expect().addText("b");
		m.expect().setCol(2);
		m.expect().addText("ell");
		m.expect().setCol(1);
		m.expect().addText("y");
		m.expect().addCr();
		m.expect().addParagraph();
		m.expect().setKern(0);
		m.expect().addText("cheese");

		send("hello[p][k7]b[c2]ell[c1]y[n][p][k]cheese", m);
	}

	public void test3() throws Exception {
		Mock<TextDest> m = Mock.mock(TextDest.class);
		m.expect().addText("hello");
		m.expect().addTable(3, 7);
		m.expect().endCell();
		m.expect().endCell();
		send("hello[t3,7][e][e]", m);
	}

	private void send(String input, Mock<TextDest> m) {
		OsdParser p = new OsdParser(m.test());
		p.parse(input);
		m.expectDone();
	}
}
