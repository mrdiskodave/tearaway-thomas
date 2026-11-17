package com.nney.micromock;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

final class RecordingInvocationHandler implements InvocationHandler {
	List<Event> events = new ArrayList<>();
	private Object rc;
	private int pos;

	@Override
	public Object invoke(Object arg0, Method method, Object[] args) throws Throwable {
		if (args == null) args = new Object[0];
		Object r = rc;
		rc = null;
		events.add(new Event(r, method, args));
		return r;
	}

	public void queueRc(Object rc) {
		this.rc = rc;
	}

	public boolean hasNext() {
		return pos < events.size();
	}

	public Event next() {
		return events.get(pos++);
	}
}