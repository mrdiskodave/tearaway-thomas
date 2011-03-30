package com.nney.json;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import junit.framework.TestCase;

import com.nney.utils.ClassResourceOpenable;
import com.nney.utils.StringIO;

public class JsonParserTest extends TestCase {
	public void testMain() throws Exception {
		String s = StringIO.loadText(new ClassResourceOpenable(JsonParserTest.class, "def.txt"),
				null);
		JsonValue v = JsonValue.parse(s);
		System.out.println(s);
		System.out.println(v.requireField("anims").requireElement(0).requireField("name").requireString());
		
		v = JsonValue.parse("true\n");
		System.out.println(v.requireBoolean());

		v = JsonValue.parse("true");
		System.out.println(v.requireBoolean());

		v = JsonValue.parse("pooh");
		System.out.println(v.requireString());
	}
}
