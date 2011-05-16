package com.nney.tt.mapper;

import java.util.ArrayList;

import com.nney.tt.geom.Coord;

/**
 * Control point manager for a given type T.
 * @param <T>
 */
public interface CPM<T> {
	ArrayList<Coord> makePoints(T t);
}
