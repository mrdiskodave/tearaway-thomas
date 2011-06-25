package com.nney.json;

import junit.framework.TestCase;

public class JsonDataDestinationTest extends TestCase {
//	public void test1() throws Exception {
//		JsonDataDestination j = new JsonDataDestination();
//		j.write(false);
//		j.write(true);
//		j.write(5);
//		j.write(-99);
//		j.write("\n\r\t\u0000\uffff yeah");
//		System.out.println(j);
//	}
//	
//	public void test2() throws Exception {
//		JsonDataDestination j = new JsonDataDestination();
//		j.beginArray();
//		j.write(false);
//		j.write(true);
//		j.write(5);
//		j.write(-99);
//		j.write("\n\r\t\u0000\uffff yeah");
//		j.end();
//		System.out.println(j);
//	}

	public void test3() throws Exception {
		JsonDataDestination j = new JsonDataDestination();
		j.beginDict();
		j.write("hello");
		j.write(true);
		j.write("yeah!");
		j.write(5);
		j.end();
		assertEquals("{ \"hello\": true, \"yeah!\": 5 }", j.toString());
	}

	public void testIntArray() {
		JsonDataDestination j = new JsonDataDestination();
		j.beginArray();
		j.write(1);
		j.write(2);
		j.write(3);
		j.end();
		assertEquals("[ 1, 2, 3 ]", j.toString());
	}
	
	public void test4() throws Exception {
		JsonDataDestination j = new JsonDataDestination();
		j.beginDict();
		j.write("hello");
		j.write(true);
		j.write("yeah");
		j.beginArray();
		j.end();
		j.write("a");
		j.write(5);
		j.end();
		System.out.println(j.toString());
	}

}
