package com.nney.tt.mapper;

public interface FieldAccessor {
	Object get();

	Object getCopy();

	void put(Object x);
}
