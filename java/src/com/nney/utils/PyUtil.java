package com.nney.utils;

import java.security.InvalidParameterException;

public class PyUtil {
	public static Iterable<Integer> range(final int start, final int stop, final int step) {
		if (step == 0) {
			throw new InvalidParameterException("range: 'step' cannot be zero");
		}
		ReadOnlyIterator<Integer> i = new ReadOnlyIterator<>() {
			int pos = start;

			@Override
			public boolean hasNext() {
				if (step > 0) return pos < stop;
				return pos > stop;
			}

			@Override
			public Integer next() {
				int answer = pos;
				pos += step;
				return answer;
			}
		};
		return ListUtil.iteratorToIteratable(i);
	}

	public static Iterable<Integer> reversedRange(int start, int stop, int step) {
		return range(stop - step, start - step, -step);
	}

	public static Iterable<Integer> range(int stop) {
		return range(0, stop, 1);
	}

	public static Iterable<Integer> reversedRange(int stop) {
		return reversedRange(0, stop, 1);
	}

	public static Iterable<Integer> range(int start, int stop) {
		return range(start, stop, 1);
	}

	public static Iterable<Integer> reversedRange(int start, int stop) {
		return reversedRange(start, stop, 1);
	}
}
