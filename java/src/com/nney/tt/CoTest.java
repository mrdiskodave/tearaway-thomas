package com.nney.tt;

import junit.framework.TestCase;

public class CoTest extends TestCase {
	public void test() throws Exception {
		CoHub hub = new CoHub();
		Coroutine main = new Coroutine(hub, "main") {
			@Override
			public void go() {
				for (int x=0; x<5; x++) {
					pause();
					System.out.println("X"+x);
				}
			};
		};
		hub.add(main);
		
		for (int y=0; y<5; y++) {
			System.out.println("y"+y);
		}
	}

}
