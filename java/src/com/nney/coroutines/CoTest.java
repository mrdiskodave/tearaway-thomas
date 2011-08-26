package com.nney.coroutines;

import junit.framework.TestCase;

public class CoTest extends TestCase {
	public void test() throws Exception {
		CoHub hub = new CoHub();
		Coroutine main = new Coroutine(hub, "main") {
			@Override
			public void go() {
				for (int x=0; x<5; x++) {
					System.out.println("  x"+x);
					pause();
				}
			};
		};
		hub.add(main);
		
		for (int y=0; y<8; y++) {
			System.out.println("y"+y);
			hub.step();
		}
	}

}
