package com.nney.utils;

public interface SortKeyGenerator<T, K> {
	K gen(T t);
}