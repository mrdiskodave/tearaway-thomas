package com.nney.utils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

public class ListUtil {
	@SuppressWarnings("unchecked")
	public static <T> T findOne(Class<T> lookingFor, Iterable<?> it) {
		for (Object o : it) {
			if (lookingFor.isInstance(o)) {
				return (T) o;
			}
		}
		return null;
	}

	@SuppressWarnings("unchecked")
	public static <T> List<T> findMany(Class<T> type, Iterable<?> it) {
		ArrayList<T> answer = new ArrayList<>();
		for (Object o : it) {
			if (type.isInstance(o)) {
				answer.add((T) o);
			}
		}
		return answer;
	}

	public static <T> int count(Class<T> type, Iterable<?> it) {
		int answer = 0;
		for (Object o : it) {
			if (type.isInstance(o)) answer++;
		}
		return answer;
	}

	public static <T> void copy(List<? super T> dest, Iterable<? extends T> src) {
		for (T t : src) {
			dest.add(t);
		}
	}

	public static <T, K extends Comparable<? super K>> void sort(List<T> src, SortKeyGenerator<T, K> skg) {
		ArrayList<PairedWithKey<T, K>> kl = new ArrayList<>();
		for (T t : src) {
			kl.add(new PairedWithKey<>(t, skg.gen(t)));
		}
		Collections.sort(kl);
		src.clear();
		for (PairedWithKey<T, K> kt : kl) {
			src.add(kt.t);
		}
	}

	public static <T> Iterable<T> reversed(final List<T> l) {
		final ReadOnlyIterator<T> i = new ReadOnlyIterator<>() {
			// could use a ListIterator but why?
			int pos = l.size();

			@Override
			public boolean hasNext() {
				return pos != 0;
			}

			@Override
			public T next() {
				return l.get(--pos);
			}
		};
		return iteratorToIteratable(i);
	}

	public static <T> Iterable<T> iteratorToIteratable(final Iterator<T> i) {
		return new Iterable<>() {
			@Override
			public Iterator<T> iterator() {
				return i;
			}
		};
	}

	public static <T> String toString(Iterable<T> iterable, String seperator) {
		StringBuilder sb = new StringBuilder();
		for (T item : iterable) {
			if (sb.length() != 0) sb.append(seperator);
			sb.append(item);
		}
		return sb.toString();
	}

	public static <T> String toString(Iterable<T> iterable) {
		return toString(iterable, ",");
	}

}
