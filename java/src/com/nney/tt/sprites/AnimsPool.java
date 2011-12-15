package com.nney.tt.sprites;

import java.util.ArrayList;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import com.nney.datanode.Node;
import com.nney.tt.gfx.Disposable;
import com.nney.tt.gfx.GraphicsContext;
import com.nney.tt.resources.TTResource;

public class AnimsPool implements Disposable {
	private final TreeMap<String, Anims> pool = new TreeMap<String, Anims>();
	private final AnimsDefPool sdp;
	private final GraphicsContext gc;

	public AnimsPool(GraphicsContext gc, AnimsDefPool sdp) {
		this.sdp = sdp;
		this.gc = gc;
	}

	public Anims expect(String k) {
		return get(k, false);
	}

	public Anims load(String k) {
		return get(k, true);
	}

	private Anims get(String k, boolean loadingPermitted) {
		Anims answer = pool.get(k);
		if (answer == null) {
			if (!loadingPermitted) {
				throw new RuntimeException("Graphic " + k + " should have been loaded already");
			}
			answer = loadAnims(k);
			pool.put(k, answer);
		}
		return answer;
	}

	private Anims loadAnims(final String animsName) {
		final boolean makeWhiteVersion = animsName == "0tt";
		// TODO: fix ^this^ hack?

		// we'll be loading the same frame twice if the animation goes
		// back on itself (e.g. ladder climbing) so we'll need a cache
		CachedLoader<Integer, Sprite> frameLoader = new CachedLoader<Integer, Sprite>() {
			@Override
			protected Sprite internalLoad(Integer k) {
				return LargeImageFrameLoader.load(gc, TTResource.animSprite(animsName, k), makeWhiteVersion);
			}
		};

		ArrayList<Anim> an = new ArrayList<Anim>();
		Node diRoot = sdp.load(animsName);
		if (diRoot == null) {
			Sprite[] frames = new Sprite[] { LargeImageFrameLoader.load(gc, TTResource.bareSprite(animsName),
					makeWhiteVersion) };
			an.add(new Anim(0, frames, 0, null));
		}
		else {
			for (Node diAnim : diRoot.requireField("anims").requireList()) {
				Node[] diFrames = diAnim.requireField("frames").requireList();
				Sprite[] frames = new Sprite[diFrames.length];
				for (int x = 0; x < frames.length; x++) {
					int fno = diFrames[x].requireInt();
					frames[x] = frameLoader.load(fno);
				}
				String name = null;
				if (diAnim.fieldExists("name")) {
					name = diAnim.requireField("name").requireString();
				}
				int rate = 0;
				if (diAnim.fieldExists("rate")) {
					rate = diAnim.requireField("rate").requireInt();
				}
				int repeatPos = -1;
				if (diAnim.fieldExists("repeatPos")) {
					repeatPos = diAnim.requireField("repeatPos").requireInt();
				}
				if (repeatPos < 0 && frames.length > 1) {
					System.out.println("ODD: " + name + " has " + frames.length + "frames but doesn't repeat");
				}
				an.add(new Anim(rate, frames, repeatPos, name));
			}
		}
		return new Anims(an);
	}

	public void unloadReload(Set<String> needs) {
		// kick out the ones we don't need
		Set<String> removes = new TreeSet<String>();

		Set<String> haves = pool.keySet();
		for (String have : haves) {
			if (!needs.contains(have)) {
				removes.add(have);
			}
		}
		for (String remove : removes) {
			pool.get(remove).dispose();
			pool.remove(remove);
		}
		// ^ done in two passes to avoid changing a structure
		// while we read it (keySet just returns a live view)

		// then load the ones we do
		for (String need : needs) {
			load(need);
		}
	}

	@Override
	public void dispose() {
		unloadReload(new TreeSet<String>());
	}
}
