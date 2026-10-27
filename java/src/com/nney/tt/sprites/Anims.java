package com.nney.tt.sprites;

import java.util.ArrayList;

import com.nney.tt.Bounded;
import com.nney.tt.BoundedUtils;
import com.nney.tt.geom.Box;
import com.nney.tt.gfx.Disposable;

public final class Anims implements Disposable, Bounded {
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

	/** How many animations there are. */
	public int size() {
		return anims.size();
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

	@Override
	public Box getBounds() {
		return BoundedUtils.collect(anims);
	}

	static public String directionalAnimName(boolean goLeft, String base) {
		return base + (goLeft ? "left" : "right");
	}
}
