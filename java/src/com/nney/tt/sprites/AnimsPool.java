package com.nney.tt.sprites;

import java.util.ArrayList;

import com.nney.json.DataItem;
import com.nney.tt.gfx.GraphicsContext;
import com.nney.tt.resources.TTResource;

public class AnimsPool extends CachedLoader<String, Anims> {
	private final AnimsDefPool sdp;
	private final GraphicsContext gc;

	public AnimsPool(GraphicsContext gc, AnimsDefPool sdp) {
		this.sdp = sdp;
		this.gc = gc;
	}

	@Override
	protected Anims populatePool(String animsName) {
		Anims answer = loadSpriteSet(animsName);
		pool.put(animsName, answer);
		return answer;
	}

	private Anims loadSpriteSet(final String animsName) {
		ArrayList<Anim> an = new ArrayList<Anim>();
		
		DataItem diRoot = sdp.load(animsName);
		final boolean makeWhiteVersion = animsName == "0tt";
		// TODO: fix ^this^ hack
		
		// we'll be loading the same frame twice if the animation goes
		// back on itself (e.g. ladder climbing) so we'll need a cache
		CachedLoader<Integer, Sprite> frameLoader = new CachedLoader<Integer, Sprite>() {
			@Override
			protected Sprite populatePool(Integer k) {
				return LargeImageFrameLoader.load(gc, TTResource.spriteFrame(animsName, k), makeWhiteVersion);
			}};

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

}
