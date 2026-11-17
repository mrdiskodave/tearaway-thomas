package com.nney.tt.lwjgl;

import java.util.HashMap;
import java.util.HashSet;

class MultiCountingSet<K, V> {
	private HashMap<K, HashSet<V>> hs = new HashMap<>();

	void add(K k, V v) {
		HashSet<V> s = hs.get(k);
		if (s == null) {
			s = new HashSet<>();
			hs.put(k, s);
		}
		s.add(v);
	}

	void remove(K k, V v) {
		HashSet<V> s = hs.get(k);
		if (s != null) {
			s.remove(v);
			if (s.isEmpty()) {
				hs.remove(k);
			}
		}
	}

	boolean contains(K k) {
		return hs.containsKey(k);
	}
}
