package com.nney.tt.sounds;

public class Loop {
	public final Sound begin;
	public final Sound loop;

	Loop(Sound begin, Sound loop) {
		if (begin==null) throw new IllegalArgumentException();
		this.begin = begin;
		this.loop = loop;
	}

	public boolean hasLoop() {
		return loop!=null;
	}
}