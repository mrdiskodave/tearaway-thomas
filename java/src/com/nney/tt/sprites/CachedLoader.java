package com.nney.tt.sprites;

import java.util.Map;
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
	
	public Map<K, V> getOurMapOut() {
		return pool;
	}

	protected abstract V populatePool(K k);
}
