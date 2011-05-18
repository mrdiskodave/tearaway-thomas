package com.nney.tt.mapper;

public class PropDrawer {
	private final MapperGC mgc;
	private int y;

	public PropDrawer(MapperGC mgc) {
		this.mgc = mgc;
	}

	public void draw(String t, String v) {
		String s = padTo(t, 10) + padTo(v, 30);
		mgc.drawText(0, y, 0xffffff, 0x60000000, s);
		y += 8;
		// TODO: 00: return a Box to say where it is
	}

	public void draw(Prop p) {
		draw(p.name(), p.text());
	}

	private static String padTo(String s, int x) {
		int l = s.length();
		StringBuffer b = new StringBuffer(s.substring(0, Math.min(x, l)));
		while (l < x) {
			b.append(' ');
			l++;
		}
		return b.toString();
	}

}
