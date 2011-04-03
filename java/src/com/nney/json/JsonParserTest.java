package com.nney.json;

import junit.framework.TestCase;

import com.nney.utils.ClassResourceOpenable;
import com.nney.utils.StringIO;

public class JsonParserTest extends TestCase {
	public void testMain() throws Exception {
		JsonValue v;
		
		v = JsonValue.parse("\"\\u004a\"");
		assertEquals("J", v.requireString());

		v = JsonValue.parse("\"\\u004A\"");
		assertEquals("J", v.requireString());

		v = JsonValue.parse("\"\\uffff\"");
		assertEquals("\uffff", v.requireString());

		v = JsonValue.parse("42");
		assertEquals(42, v.requireInt());

		v = JsonValue.parse("[ 42, 43 ]");
		assertEquals(42, v.requireElement(0).requireInt());
		assertEquals(43, v.requireElement(1).requireInt());

		v = JsonValue.parse("{ \"d\":42, \"c\":43 }");
		assertEquals(42, v.requireField("d").requireInt());
		assertEquals(43, v.requireField("c").requireInt());
		
		v = JsonValue.parse("true\n");
		assertTrue(v.requireBoolean());

		v = JsonValue.parse("true");
		assertTrue(v.requireBoolean());

		v = JsonValue.parse("\"pooh\"");
		assertEquals("pooh", v.requireString());

		String s = StringIO.loadText(new ClassResourceOpenable(JsonParserTest.class, "def.txt"),
				null);
		v = JsonValue.parse(s);
		System.out.println(s);
		assertEquals("runright", v.requireField("anims").requireElement(0).requireField("name").requireString());
		

	}
}
