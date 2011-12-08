package com.nney.micromock;

import java.lang.reflect.Method;

class Event {
	public final Method method;
	public final Object[] args;
	public final Object rc;

	Event(Object rc, Method method, Object[] args) {
		this.rc = rc;
		this.method = method;
		this.args = args;
	}
}