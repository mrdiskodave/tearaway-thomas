package com.nney.tt.mapper;

import java.util.List;

/**
 * 
 * A carousel for leafing through a list of things.
 * 
 * <p>
 * What is interesting is that the list on which we are constructed can be
 * changed elsewhere and we keep working just so long as a) the list is is never
 * empty 2) following the first call to {@link #get()}: the value last returned
 * from this method must remain in the list.
 * 
 * @param <T>
 *            The type of the thing.
 */
public class Carousel<T> {
	private List<T> list;
	private T current;

	Carousel(List<T> list) {
		this.list = list;
	}

	private Carousel(List<T> list2, T t) {
		list = list2;
		current = t;
		validateAndInit();
	}

	private void validateAndInit() {
		assert !list.isEmpty();
		if (current == null) current = list.get(0);
		assert list.contains(current);
	}

	public T get() {
		validateAndInit();
		return current;
	}

	public void next() {
		validateAndInit();
		moveBy(1);
	}

	public void prev() {
		validateAndInit();
		moveBy(-1);
	}

	private void moveBy(int i) {
		validateAndInit();
		int idx = getPos();
		int s = list.size();
		idx += i + s;
		idx %= s;
		current = list.get(idx);
	}

	public int getPos() {
		validateAndInit();
		return list.indexOf(get());
	}

	public Carousel<T> copy() {
		validateAndInit();
		return new Carousel<T>(list, current);
	}

	public void find(T typeCode) {
		validateAndInit();
		current = typeCode;
		getPos();
	}
}
