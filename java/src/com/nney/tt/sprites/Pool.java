package com.nney.tt.sprites;

import java.util.HashMap;
import java.util.Set;

public abstract class Pool<V> {
	protected HashMap<String, V> pool = new HashMap<String, V>();

	public V load(String k) {
		V v = pool.get(k);
		if (v == null) {
			v = internalLoad(k);
			pool.put(k, v);
		}
		return v;
	}

	public boolean cached(String k) {
		return pool.containsKey(k);
	}
	
	public Set<String> keySet() {
		return pool.keySet();
		// TODO: who is doing the GC here?
		// if the animPool releases an animation -- all the sprites get decremented
		// and some are removed but how does the spritePool learn about this?
		// gah!!
		// they are owned at the SpritePool level
		// the Anim has a list of numbers
		// and then temporarilly establishes a list of Sprites for in game action!
	}

	protected abstract V internalLoad(String k);
}
