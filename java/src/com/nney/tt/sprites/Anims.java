package com.nney.tt.sprites;

import java.util.ArrayList;

import com.nney.tt.gfx.Disposable;

public class Anims implements Disposable {
	private final ArrayList<Anim> anims;
	public final String spriteName;

	public Anims(String spriteName, ArrayList<Anim> animList) {
		this.spriteName = spriteName;
		this.anims = animList;
	}

	public Anim find(String name) {
		for (Anim anim : anims) {
			if (anim.name!=null && anim.name.equals(name)) {
				return anim;
			}
		}
		throw new RuntimeException("Cannot find: " + name);
	}

	public Anim find(int pos) {
		return anims.get(pos);
	}

	@Override
	public void dispose() {
		for (Anim anim: anims) {
			anim.dispose();
		}
	}
}
