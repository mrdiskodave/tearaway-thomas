package com.nney.tt.mapper;

public abstract class SpecificProp<T> extends Prop {
	SpecificProp(PropPack pp) {
		super(pp);
	}

	@SuppressWarnings("unchecked")
	public T read() {
		return (T) getFieldAccessor().get();
	}

	public void write(T n) {
		getFieldAccessor().put(n);
	}
}
