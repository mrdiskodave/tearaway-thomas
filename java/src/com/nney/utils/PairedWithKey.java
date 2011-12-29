package com.nney.utils;

class PairedWithKey<T, K extends Comparable<? super K>> implements Comparable<PairedWithKey<T, K>> {
	final T t;
	final K k;

	PairedWithKey(T t, K k) {
		this.t = t;
		this.k = k;
	}

	@SuppressWarnings("unchecked")
	@Override
	public boolean equals(Object obj) {
		return compareTo((PairedWithKey<T, K>) obj) == 0;
	}

	@Override
	public int compareTo(PairedWithKey<T, K> o) {
		return k.compareTo(o.k);
	}
}
