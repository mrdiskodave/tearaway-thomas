package com.nney.tt.sprites;

import java.util.ArrayList;

import com.nney.tt.gfx.Disposable;

public class Anims implements Disposable {
	private final ArrayList<Anim> anims;

	public Anims(ArrayList<Anim> animList) {
		this.anims = animList;
	}

	public Anim mightFind(String name) {
		for (Anim anim : anims) {
			if (anim.name != null && anim.name.equals(name)) {
				return anim;
			}
		}
		return null;
	}

	public Anim find(String name) {
		Anim answer = mightFind(name);
		if (answer == null) {
			throw new RuntimeException("Cannot find: " + name);
		}
		return answer;
	}

	public Anim find(int pos) {
		return anims.get(pos);
	}

	@Override
	public void dispose() {
		for (Anim anim : anims) {
			anim.dispose();
		}
	}
}
