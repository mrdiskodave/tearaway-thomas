package com.nney.tt.mapper;

import java.lang.reflect.Field;

public class FieldAccessor {
	private final Field f;
	private final Object o;

	public FieldAccessor(Field f, Object o) {
		this.f = f;
		this.o = o;
	}

	public Object get() {
		try {
			return f.get(o);
		}
		catch (IllegalArgumentException e) {
			throw new RuntimeException(e);
		}
		catch (IllegalAccessException e) {
			throw new RuntimeException(e);
		}
	}

	public void put(Object o, Object v) {
		try {
			f.set(o, v);
		}
		catch (IllegalArgumentException e) {
			throw new RuntimeException(e);
		}
		catch (IllegalAccessException e) {
			throw new RuntimeException(e);
		}
	}

}
