package com.nney.tt;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.NoSuchElementException;

public class ConcatenatedIterator<T> implements Iterator<T> {
	ArrayList<Iterator<T>> content = new ArrayList<Iterator<T>>();
	
	void add(Iterator<T> t) {
		content.add(t);
	}

	void add(Iterable<T> t) {
		add(t.iterator());
	}

	@Override
	public boolean hasNext() {
		for (;;) {
			if (content.isEmpty()) return false;
			if (content.get(0).hasNext()) return true;
			content.remove(0);
		}
	}

	@Override
	public T next() {
		if (!hasNext()) throw new NoSuchElementException();
		return content.get(0).next();
	}

	@Override
	public void remove() {
		content.get(0).remove();
	}
}
