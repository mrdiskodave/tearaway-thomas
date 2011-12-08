package com.nney.micromock;

import junit.framework.TestCase;

public class MockTest extends TestCase {
	interface E {
		void a(int j);

		void b();

		int c();
	}

	public static void testMain() {
		Mock<E> m = Mock.mock(E.class);
		m.expect().a(3);
		m.expect().b();
		m.expectThenReturn(4).c();

		E e = m.test();
		e.a(3);
		e.b();
		assertEquals(4, e.c());
		m.done();
	}
}
