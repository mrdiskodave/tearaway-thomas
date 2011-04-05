package com.nney.tt.sprites;

import java.util.ArrayList;

public class SpriteSet {
	final ArrayList<Anim> animList;

	public SpriteSet(ArrayList<Anim> animList) {
		this.animList = animList;
	}

	public Anim find(String name) {
		for (Anim anim : animList) {
			if (anim.name.equals(name)) {
				return anim;
			}
		}
		throw new RuntimeException("Cannot find: "+name);
	}
	
	public Anim find(int pos) {
		return animList.get(pos);
	}
}
