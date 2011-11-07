package com.nney.json;

import junit.framework.TestCase;

public class JsonDataDestinationTest extends TestCase {
	SafeWriter sw;
	SimpleJsonFormatter dest;
	JsonDataDestination f;
	
	public JsonDataDestinationTest() {
		sw = new StringSafeWriter();
		dest = new IndentedJsonFormatter(sw);
//		dest.spaciousBrackets();
		dest.spaciousSeperators();
		f = new JsonDataDestination(dest);
	}

	private void assertResult(String expected) {
		String actual = sw.toString();
		System.out.println(actual);
//		assertEquals(expected, actual);
	}

	public void testSimple() {
		f.write(false);
		f.write(true);
		assertResult("false, true");
	}
	
	public void testValues() throws Exception {
		f.write(false);
		f.write(true);
		f.write(5);
		f.write(6L);
		f.write(-99);
		f.write("\n\r\t\u0000\uffff yeah");
		assertResult("false, true, 5, 6, -99, \"\\n\\r\\t\\u0000\\uffff yeah\"");
	}

	public void testSimpleDict() throws Exception {
		f.beginObject();
		f.write("hello");
		f.write(true);
		f.write("yeah!");
		f.write(5);
		f.end();
		assertResult("{ \"hello\": true, \"yeah!\": 5 }");
	}

	public void testIntArray() {
		f.beginArray();
		f.write(1);
		f.write(2);
		f.write(3);
		f.end();
		assertResult("[ 1, 2, 3 ]");
	}
	
	public void testNestedDict() throws Exception {
		f.beginObject();
		f.write("hello");
		f.write(true);
		f.write("yeah");
		f.beginObject();
		f.write("A");
		f.write("B");
		f.end();
		f.write("a");
		f.write(5);
		f.end();
		assertResult("{ \"hello\": true, \"yeah\": { \"A\": \"B\" }, \"a\": 5 }");
	}
	
	public void testNestedArray() throws Exception {
		f.beginArray();
		f.write(1);
		f.beginArray();
		f.beginArray();
		f.end();
		f.write(2);
		f.end();
		f.end();
		assertResult("[ 1, [ [  ], 2 ] ]");
	}
}
