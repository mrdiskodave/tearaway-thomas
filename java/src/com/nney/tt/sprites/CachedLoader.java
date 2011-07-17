package com.nney.tt.sprites;

import java.util.TreeMap;

public abstract class CachedLoader<K, V> {
	TreeMap<K, V> pool = new TreeMap<K, V>();

	public V load(K k) {
		V answer = pool.get(k);
		if (answer == null) {
			answer = internalLoad(k);
			pool.put(k, answer);
		}
		return answer;
	}

	public boolean isCached(K k) {
		return pool.containsKey(k);
	}

//	public void clear() {
//		pool.clear();
//	}

	protected abstract V internalLoad(K k);
}
