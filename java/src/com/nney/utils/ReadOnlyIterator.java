package com.nney.utils;

import java.util.Iterator;

public abstract class ReadOnlyIterator<T> implements Iterator<T> {
	@Override
	public void remove() {
		throw new UnsupportedOperationException("remove() forbidden by ReadOnlyIterator");
	}

	public static <T> ReadOnlyIterator<T> wrap(final Iterator<T> target) {
		return new ReadOnlyIterator<T>() {
			@Override
			public boolean hasNext() {
				return target.hasNext();
			}

			@Override
			public T next() {
				return target.next();
			}
		};
	}
}
