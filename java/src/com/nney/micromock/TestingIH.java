package com.nney.micromock;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;

final class TestingIH implements InvocationHandler {
	private final RecordingIH rih;

	public TestingIH(RecordingIH rih) {
		this.rih = rih;
	}

	@Override
	public Object invoke(Object arg0, Method method, Object[] args) throws Throwable {
		if (args == null) args = new Object[0];
		if (!rih.hasNext()) {
			throw new AssertionError("Too many calls");
		}
		Event e = rih.next();
		{
			Method a = method;
			Method x = e.method;
			if (!e.method.equals(method)) {
				throw new AssertionError(String.format("Expected %s() but got %s()", x.getName(), a.getName()));
			}
		}
		{
			int a = e.args.length;
			int x = args.length;
			if (a != x) {
				throw new AssertionError(String.format("Expected %s() argument count %s but got %s",
						e.method.getName(), x, a));

			}
		}
		{
			for (int j = 0; j < e.args.length; j++) {
				Object a = args[j];
				Object x = e.args[j];
				if (!a.equals(x)) {
					throw new AssertionError(String.format("Expected %s() argument#%s of %s but got %s",
							e.method.getName(), j + 1, x, a));
				}
			}
		}
		return e.rc;
	}

	public void done() {
		if (rih.hasNext()) {
			throw new AssertionError("Not enough calls");
		}
	}
}