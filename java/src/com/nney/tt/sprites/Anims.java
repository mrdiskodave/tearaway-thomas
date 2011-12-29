package com.nney.tt.sprites;

import java.util.ArrayList;

import com.nney.tt.geom.Box;
import com.nney.tt.gfx.Disposable;

public final class Anims implements Disposable {
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

	public Box box() {
		Box answer = null;
		for (Anim anim : anims) {
			Box b = anim.box();
			if (answer == null) {
				answer = b;
			}
			else {
				answer.accommodate(b);
			}
		}
		return answer;
	}

	static public String directionalAnimName(boolean goLeft, String base) {
		return base + (goLeft ? "left" : "right");
	}
}
