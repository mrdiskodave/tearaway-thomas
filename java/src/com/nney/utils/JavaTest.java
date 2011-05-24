/*
 * This file originates from Digitalbrain PLC.
 * 
 * Digitalbrain PLC made the following agreement with me ...
 * 
 * "Digitalbrain hereby grant me [David Hanney] a license to use
 * The Libraries [which include this file] in perpetuity for any
 * purpose without any restriction. This includes, strictly without
 * limitation, the rights to use, copy, modify, merge, publish,
 * distribute, sell or sublicense."
 *
 * David Hanney (26/01/2005)
 */

package com.nney.utils;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.TreeMap;
import java.util.Vector;
import java.util.regex.Pattern;

import junit.framework.TestCase;

/**
 * 
 */
public class JavaTest extends TestCase {

	/*
	 * Tests written at Digitalbrain.. testing.
	 */

	public void testArraysAreObjects() {
		byte[] b = new byte[1];
		b[0] = 5;
		Object o = b;
		byte[] c = (byte[]) o;
		assertEquals(c[0], 5);
	}

	public void testIntsWrapAround() {
		int v = 0;
		for (int x = 0; x < 100; x++) {
			v += 0x10000000;
			if (v < 0) return;
		}
		fail("taking too long");
	}

	public void testVectorIteratorsSupportRemove() {
		Vector<String> v = new Vector<String>();
		String a = "1";
		String b = "2";
		String c = "3";
		v.add(a);
		v.add(b);
		v.add(c);
		Iterator<String> i = v.iterator();
		assertTrue(i.hasNext());
		i.next(); // element 0
		assertTrue(i.hasNext());
		i.next(); // element 1
		i.remove(); // BLAMM!!

		// but is the aftermath what we expected?
		assertEquals(2, v.size());
		assertEquals(a, v.get(0));
		assertEquals(c, v.get(1));
	}

	public void testShiftCountIsModuloBitCount() {
		int x = 1;
		x >>= 256; // shifts by zero bits!
		assertEquals(1, x);
	}

	/**
	 * I've got a byte shiftregister - this test confirms that unique
	 * shiftregister-values associate with unique byte combinations <b>even if I
	 * don't care that Java sign extends the bytes</b>(!)
	 * 
	 * I find this a bit counterintuitive (hence the need for this test).
	 * 
	 * Why does this work? Well, if a byte comes in bigger than 127 it will be
	 * signed extended. e.g. 255 becomes -1. -1 decrements the shift-register
	 * which knocks one off the value which we previously shifted in. However I
	 * think this "information lost" is expressed in the resuling lower-order
	 * byte so it works out that no information is <i>really</i> lost.
	 * 
	 * This fact is exploited in the hash used in my antivirus scanner. (so it
	 * is a good thing that it <b>is</b> fact;)
	 */
	public void testByteShiftRegisterSigned() {
		boolean[] seen = new boolean[0x1000000];
		for (int t = 0; t < 0x1000000; t++) {
			byte a = (byte) t;
			byte b = (byte) (t >> 8);
			byte c = (byte) (t >> 16);
			int x = 0;
			x += a;
			x <<= 8;
			x += b;
			x <<= 8;
			x += c;
			x &= 0xffffff;
			assertFalse(seen[x]);
			seen[x] = true;
		}
	}

	public void testEqualsDoesntTestArrayContent() {
		byte[] a = new byte[1];
		byte[] b = new byte[1];
		a[0] = 55;
		b[0] = 55;
		assertFalse(a.equals(b));
	}

	/*
	 * Tests after Digialbrain.
	 */

	public void testFromObject() {
		Object a = new Integer(5);
		Integer b = (Integer) a;
		assertTrue(a == b);
	}

	public void testNullFromObject() {
		Object a = null;
		Integer b = (Integer) a;
		assertNull(b);
	}

	public void testFloatRounding() {
		float a = 1.0f;
		float b = 1.1f;
		float c = 1.9f;
		assertEquals(1, (int) a);
		assertEquals(1, (int) b);
		assertEquals(1, (int) c);

		assertEquals(1, (int) Math.ceil(a));
		assertEquals(2, (int) Math.ceil(b));
		assertEquals(2, (int) Math.ceil(c));

		assertEquals(1, (int) Math.floor(a));
		assertEquals(1, (int) Math.floor(b));
		assertEquals(1, (int) Math.floor(c));

		assertEquals(1, (int) Math.rint(a));
		assertEquals(1, (int) Math.rint(b));
		assertEquals(2, (int) Math.rint(c));
	}

	public void testParseSmallHex() {
		assertEquals(0x7fffffff, Integer.parseInt("7fffffff", 16));
	}

	public void testParseBigHex() {
		try {
			assertEquals(0x80000000, Integer.parseInt("80000000", 16));
			fail();
		}
		catch (NumberFormatException e) {
			// thought so
		}
	}

	public void testLongHexDoesntNotRoundTripGotcha() {
		try {
			long expected = -1;
			String asString = Long.toHexString(expected);
			Long.parseLong(asString, 16); // bang!!
			fail();
		}
		catch (NumberFormatException e) {
			// expected (at least, now that I understand this gotcha!)
		}
	}

	static private String method(Object x) {
		return "Any " + x;
	}

	static private String method(Integer x) {
		return "Integer " + x;
	}

	public void testArgOverloading() {
		assertEquals("Any 5", method(new Long(5)));
		assertEquals("Any old cheese", method("old cheese"));
		assertEquals("Integer 5", method(new Integer(5)));
	}

	public void testByteSignExtends() {
		byte b = (byte) 0xff;
		int i = b;
		assertEquals(-1, i);
	}

	public void testArrayEqualsGotcha() {
		byte[] a = new byte[1];
		byte[] b = new byte[1];
		a[0] = 7;
		b[0] = 7;
		assertFalse(a == b);
		assertFalse(a.equals(b)); // noooooo!!!! that's not at all like String
	}

	public void testArraysDontUpCast() {
		try {
			Object[] a = new Object[] { "hello" };
			String[] b = (String[]) a;
			assertEquals("hello", b[0]);
			fail();
		}
		catch (ClassCastException e) {
			// expected
		}
	}

	public void testDoDownCast() {
		String[] s = { "one" };

		Object[] o = s;
		assertEquals(o[0], "one");

		String[] back = (String[]) o;
		assertEquals(back[0], "one");
		/*
		 * That works only because it actually *is* a String[]. Where as the
		 * code above fails because it is a Object[].
		 */
	}

	public void testArrayException() {
		try {
			byte[] b = new byte[0];
			b[0] = 1;
			fail();
		}
		catch (ArrayIndexOutOfBoundsException e) {
			// expected
		}
	}

	public void testVectorCopyCtorActuallyCopies() {
		// as I suspect it might reference and the docs are not entirely clear
		Vector<String> a = new Vector<String>();
		a.add("lion");
		a.add("unicorn");
		Vector<String> b = new Vector<String>(a);
		b.set(0, "upfront");

		assertEquals("lion", a.get(0));
		assertEquals("unicorn", a.get(1));
		assertEquals("upfront", b.get(0));
		assertEquals("unicorn", b.get(1));
	}

	public void testAssertsWorkBroken() {
		try {
			assert false;
			fail("still here");
		}
		catch (Throwable e) {
			// expected
		}
	}

	public void testPrecedence() {
		// + happens first
		assertEquals(32, 1 << 4 + 1);

		// * happens first
		assertEquals(16, 1 << 2 * 2);

		// & happens first (so need brackets)
		assertTrue((1 & 3) == 1);
	}

	public void testTotalMatch() {
		boolean matches = Pattern.compile("lar").matcher("lard").matches();
		assertFalse(matches);
	}

	public void testTotalMatchConcise() {
		boolean matches = "lard".matches("lar");
		assertFalse(matches);
	}

	public void testSlidingMatch() {
		boolean matches = Pattern.compile("lar").matcher("lard").find();
		assertTrue(matches);
	}

	/*
	 * There seems to be no SlidingMatchConcise which is rather vexing.
	 */

	/**
	 * Show that you cannot put <code>null</code> keys into a map. (for a while
	 * I thought you could)
	 */
	public void testNullKeys() throws Exception {
		try {
			TreeMap<String, String> c = new TreeMap<String, String>();
			c.put("name", "david");
			c.put(null, "yeah");
			c.put("age", "34");
			fail();
		}
		catch (NullPointerException e) {
			// expected
		}
	}

	public void testRepeatingYourself() {
		int counter = 0;

		int x = 42;
		do {
			counter++;
		} while (--x > 0);

		assertEquals(42, counter);
	}

	public void testShortComposition() {
		int xz = 0;
		for (int h = 0; h < 256; h++) {
			for (int l = 0; l < 256; l++) {
				byte hb = (byte) h;
				byte hl = (byte) l;
				int z = ((hb & 255) << 8) + (hl & 255);
				assertEquals(xz, z);
				xz++;
			}
		}
	}

	public void testRepeatingYourself2() {
		int counter = 0;

		for (int x = 42; x-- > 0;) {
			counter++;
		}

		assertEquals(42, counter);
	}

	public void testExtend() {
		assertEquals(512, ((byte) 1) * 512);
	}

	public void testRerverse() {
		ArrayList<Integer> ohDear = new ArrayList<Integer>();
		for (int x = 0; x < 4; x++) {
			ohDear.add(x);
		}
		ArrayList<Integer> n = new ArrayList<Integer>();
		for (int x = ohDear.size(); --x >= 0;) {
			n.add(ohDear.get(x));
		}
		assertEquals(3, (int) n.get(0));
		assertEquals(2, (int) n.get(1));
		assertEquals(1, (int) n.get(2));
		assertEquals(0, (int) n.get(3));
	}
}
