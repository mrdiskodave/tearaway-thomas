package com.nney.json;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import junit.framework.TestCase;

import com.nney.utils.ClassResourceOpenable;
import com.nney.utils.StringIO;

public class JsonParserTest extends TestCase {
	private final static Pattern WHITESPACE = Pattern.compile("\\s+");
	private final static Pattern NUMBER = Pattern.compile(
			"-?(0|[1-9][0-9]*)(\\.[0-9]+)?(e[-+][0-9]+)?", Pattern.CASE_INSENSITIVE);
	private final static Pattern CONSTS = Pattern.compile("true|false|null");

	public void testMain() throws Exception {
		String s = StringIO.loadText(new ClassResourceOpenable(JsonParserTest.class, "def.txt"),
				null);
		JsonValue v = JsonValue.parse(s);
		System.out.println(s);
		System.out.println(v.requireField("anims").requireElement(0).requireField("name").requireString());
//		s = "       3.141f-34             ";
//		System.out.println(s);
//		JsonStrStream js = new JsonStrStream(s);
//
//		for (;;) {
//			js.lookingAt(WHITESPACE);
//
//			if (js.lookingAt("{")) {
//				System.out.println("OBJECT!");
//				break;
//			}
//			else if (js.lookingAt("[")) {
//				System.out.println("ARRAY!");
//				break;
//			}
//			else {
//				Matcher mNumber = js.lookingAt(NUMBER);
//				if (mNumber != null) {
//					System.out.println("NUMBER!");
//					return new JsonNumber(mNumber.group()));
//				}
//				else {
//					Matcher mConsts = js.lookingAt(CONSTS);
//					if (mConsts != null) {
//						return new Json
//
//					}
//
//				}
//			}
//
//		}

	}
}
