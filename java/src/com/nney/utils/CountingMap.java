package com.nney.utils;

import java.util.HashMap;
import java.util.Map;

public class CountingMap<T> {
	private final Map<T, Integer> counts = new HashMap<T, Integer>();

	public void clear() {
		counts.clear();
	}

	public int inc(T t) {
		Integer useCount = get(t);
		useCount++;
		counts.put(t, useCount);
		return useCount;
	}

	public void zero(T t) {
		counts.remove(t);
	}

	public int dec(T t) {
		Integer useCount = counts.get(t);
		if (useCount == null) return 0;
		useCount--;
		if (useCount == 0) {
			counts.remove(t);
		}
		else {
			counts.put(t, useCount);
		}
		return useCount;
	}

	public int get(T t) {
		Integer useCount = counts.get(t);
		if (useCount == null) useCount = 0;
		return useCount;
	}
}
