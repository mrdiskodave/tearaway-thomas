package com.nney.json;

import java.util.Random;

import junit.framework.TestCase;

import com.nney.datanode.Node;
import com.nney.utils.ClassResourceOpenable;
import com.nney.utils.StringIO;

public class JsonParserTest extends TestCase {
	public void testMain() throws Exception {
		Node v;

		v = JsonParser.parse("\"\\u004a\"");
		assertEquals("J", v.requireString());

		v = JsonParser.parse("\"\\u004A\"");
		assertEquals("J", v.requireString());

		v = JsonParser.parse("\"\\uffff\"");
		assertEquals("\uffff", v.requireString());

		v = JsonParser.parse("42");
		assertEquals(42, v.requireInt());
		
		Random r = new Random(1);
		for (int x=0; x<99999; x++) {
			long t = r.nextLong();
			v = JsonParser.parse(Long.toString(t));
			assertEquals(t, v.requireLong());
		}

		v = JsonParser.parse("[ 42, 43 ]");
		assertEquals(42, v.requireElement(0).requireInt());
		assertEquals(43, v.requireElement(1).requireInt());

		v = JsonParser.parse("42.93");
		assertEquals(42, v.requireInt());
		assertEquals(42.93, v.requireDouble());

		v = JsonParser.parse("{ \"d\":42, \"c\":43 }");
		assertEquals(42, v.requireField("d").requireInt());
		assertEquals(43, v.requireField("c").requireInt());

		v = JsonParser.parse("true\n");
		assertTrue(v.requireBoolean());

		v = JsonParser.parse("true");
		assertTrue(v.requireBoolean());

		v = JsonParser.parse("false");
		assertFalse(v.requireBoolean());

		v = JsonParser.parse("\"pooh\"");
		assertEquals("pooh", v.requireString());

		String s = StringIO.loadText(new ClassResourceOpenable(JsonParserTest.class, "def.txt"), null);
		v = JsonParser.parse(s);
		System.out.println(s);
		assertEquals("runright", v.requireField("anims").requireElement(0).requireField("name").requireString());

	}
}
