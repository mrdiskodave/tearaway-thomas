package com.nney.tt.toygen;

import java.util.HashMap;
import java.util.Map;

import com.nney.tt.gfx.SimpleImage.ChangePixel;

public class PaletteChanger implements ChangePixel {
	private final Map<Integer, Integer> map;

	PaletteChanger() {
		this.map = new HashMap<>();
	}

	void add(int s, int d) {
		map.put(s, d);
	}

	@Override
	public int change(int c) {
		Integer nc = map.get(c);
		if (nc == null) return c;
		return nc;
	}
}
