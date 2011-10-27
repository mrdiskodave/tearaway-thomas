package com.nney.utils;

import java.util.ArrayList;
import java.util.List;

public class ListUtil {
	@SuppressWarnings("unchecked")
	public static <T> T findOne(Class<T> c, List<?> l) {
		for (Object i: l) {
			if (c.isInstance(i)) {
				return (T) i;
			}
		}
		return null;
	}
	
	@SuppressWarnings("unchecked")
	public static <T> List<T> findMany(Class<T> c, Iterable<?> l) {
		ArrayList<T> answer = new ArrayList<T>();
		for (Object i: l) {
			if (c.isInstance(i)) {
				answer.add((T) i);
			}
		}
		return answer;
	}
	
}
