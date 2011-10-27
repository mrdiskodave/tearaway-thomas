package com.nney.utils;

import java.util.Iterator;

public class ReadOnlyIterator<T> implements Iterator<T> {
	private final Iterator<T> target;

	public ReadOnlyIterator(Iterator<T> target) {
		this.target = target;
	}
	
	@Override
	public boolean hasNext() {
		return target.hasNext();
	}

	@Override
	public T next() {
		return target.next();
	}

	@Override
	public void remove() {
		throw new RuntimeException("remove() forbidden on ReadOnlyIterator");
	}
}
