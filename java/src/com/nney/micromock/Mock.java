package com.nney.micromock;

import java.lang.reflect.Proxy;

public class Mock<T> {
	private Object recordingProxy;
	private RecordingIH rih;
	private Object testingProxy;
	private TestingIH tih;

	public Mock(Class<?> c) {
		rih = new RecordingIH();
		tih = new TestingIH(rih);
		recordingProxy = Proxy.newProxyInstance(c.getClassLoader(), new Class[] { c }, rih);
		testingProxy = Proxy.newProxyInstance(c.getClassLoader(), new Class[] { c }, tih);
	}

	@SuppressWarnings("unchecked")
	public T expect() {
		return (T) recordingProxy;
	}

	@SuppressWarnings("unchecked")
	public T expectThenReturn(Object rc) {
		rih.queueRc(rc);
		return (T) recordingProxy;
	}

	@SuppressWarnings("unchecked")
	public T test() {
		return (T) testingProxy;
	}

	public void expectDone() {
		tih.expectDone();
	}

	@SuppressWarnings("unchecked")
	public static <T> Mock<T> mock(Class<T> c) {
		return new Mock<T>(c);
	}
}
