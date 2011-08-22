package com.nney.tt;

import junit.framework.TestCase;

public class CoTest extends TestCase {
	public void test() throws Exception {
		Cohub hub = new Cohub();
		Coroutine main = new Coroutine(hub, "main") {
			@Override
			public void run() {
				System.out.println("I am co-routine: "+name);
			};
		};
		Coroutine secondary = new Coroutine(hub, "secondary") {
			@Override
			public void run() {
				System.out.println("I am co-routine: "+name);
			};
		};
		hub.add(main);
		hub.add(secondary);
		hub.dispatch();
	}

}
