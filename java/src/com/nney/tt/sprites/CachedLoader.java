package com.nney.tt.sprites;

import java.util.TreeMap;

public abstract class CachedLoader<K, V> {
	TreeMap<K, V> pool = new TreeMap<K, V>();
	
	public V load(K k) {
		V answer = pool.get(k);
		if (answer==null) {
			answer = populatePool(k);
		}
		return answer;
	}

	protected abstract V populatePool(K k);
}
