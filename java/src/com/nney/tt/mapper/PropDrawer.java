package com.nney.tt.mapper;

public class PropDrawer {
	private int y;
	private final StatusLayer statusLayer;

	public PropDrawer(StatusLayer statusLayer) {
		this.statusLayer = statusLayer;
	}

	public void draw(String t, String v) {
		statusLayer.draw(0, y, 0xffffffff, clip(t, 10));
		statusLayer.draw(10, y, 0xffffffff, v);
		y ++;
	}

	public void draw(Prop p) {
		draw(p.name(), p.text());
	}

	private static String clip(String s, int x) {
		return s.substring(0, Math.min(x, s.length()));
	}

}
