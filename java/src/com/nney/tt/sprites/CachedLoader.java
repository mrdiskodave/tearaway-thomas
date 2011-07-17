package com.nney.tt.sprites;

import java.util.TreeMap;

public abstract class CachedLoader<K, V> {
	protected TreeMap<K, V> pool = new TreeMap<K, V>();

	public V load(K k) {
		V answer = pool.get(k);
		if (answer == null) {
			answer = internalLoad(k);
			pool.put(k, answer);
		}
		return answer;
	}

//	public V loadUncached(K k) {
//		assert pool.containsKey(k) : "expected to find key in cache " + k;
//		return load(k);
//	}
	
	protected abstract V internalLoad(K k);
}
