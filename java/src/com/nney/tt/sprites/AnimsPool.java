package com.nney.tt.sprites;

import java.util.ArrayList;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import com.nney.json.DataItem;
import com.nney.tt.gfx.GraphicsContext;
import com.nney.tt.resources.TTResource;

public class AnimsPool {
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

	public Anims get(String k, boolean loadingPermitted) {
		Anims answer = pool.get(k);
		if (answer == null) {
			assert loadingPermitted : "expected to find key in cache " + k;
			answer = loadAnims(k);
			pool.put(k, answer);
		}
		return answer;
	}
	
	

	private Anims loadAnims(final String animsName) {
		ArrayList<Anim> an = new ArrayList<Anim>();

		DataItem diRoot = sdp.load(animsName);
		final boolean makeWhiteVersion = animsName == "0tt";
		// TODO: fix ^this^ hack

		// we'll be loading the same frame twice if the animation goes
		// back on itself (e.g. ladder climbing) so we'll need a cache
		CachedLoader<Integer, Sprite> frameLoader = new CachedLoader<Integer, Sprite>() {
			@Override
			protected Sprite internalLoad(Integer k) {
				return LargeImageFrameLoader.load(gc, TTResource.spriteFrame(animsName, k), makeWhiteVersion);
			}
		};

		for (DataItem diAnim : diRoot.requireField("anims").requireList()) {
			DataItem[] diFrames = diAnim.requireField("frames").requireList();
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
			an.add(new Anim(rate, frames, repeatPos, name));
		}
		return new Anims(animsName, an);
	}

	public void unloadReload(Set<String> animsNeeded) {
		// kick out the ones we don't need
		ArrayList<String> removes = new ArrayList<String>();
		for (String name: pool.keySet()) {
			if (!animsNeeded.contains(name)) {
				removes.add(name);
			}
		}
		for (String remove: removes) {
			pool.get(remove).dispose();
			pool.remove(remove);
		}
		
		// then load the ones we do
		for (String need: animsNeeded) {
			load(need);
		}
	}
}
