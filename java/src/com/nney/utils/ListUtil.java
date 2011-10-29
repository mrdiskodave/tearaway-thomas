package com.nney.utils;

import java.util.ArrayList;
import java.util.Collections;
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
		ArrayList<T> answer = new ArrayList<T>();
		for (Object o : it) {
			if (type.isInstance(o)) {
				answer.add((T) o);
			}
		}
		return answer;
	}

	public static <T> void copy(List<? super T> dest, Iterable<? extends T> src) {
		for (T t : src) {
			dest.add(t);
		}
	}

	public static <T, K extends Comparable<? super K>> void sort(List<T> src, SortKeyGenerator<T, K> skg) {
		ArrayList<PairedWithKey<T, K>> kl = new ArrayList<PairedWithKey<T, K>>();
		for (T t : src) {
			kl.add(new PairedWithKey<T, K>(t, skg.gen(t)));
		}
		Collections.sort(kl);
		src.clear();
		for (PairedWithKey<T, K> kt : kl) {
			src.add(kt.t);
		}
	}
}
