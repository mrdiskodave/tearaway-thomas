package com.nney.tt.sounds;

public class Loop {
	public final Sound begin;
	public final Sound loop;

	Loop(Sound begin, Sound loop) {
		this.begin = begin;
		this.loop = loop;
	}
}