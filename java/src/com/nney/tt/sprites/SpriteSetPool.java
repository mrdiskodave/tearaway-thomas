package com.nney.tt.sprites;

import java.util.ArrayList;

import com.nney.json.DataItem;
import com.nney.tt.resources.TTResource;

public class SpriteSetPool extends CachedLoader<String, SpriteSet> {
	private final SpriteDefPool sdp;

	public SpriteSetPool(SpriteDefPool sdp) {
		this.sdp = sdp;
	}

	@Override
	protected SpriteSet populatePool(String spriteName) {
		SpriteSet answer = loadSpriteSet(spriteName);
		pool.put(spriteName, answer);
		return answer;
	}

	private SpriteSet loadSpriteSet(final String spriteName) {
		ArrayList<Anim> an = new ArrayList<Anim>();
		
		// we'll be loading the same frame twice if the animation goes
		// back on itself (e.g. ladder climbing) so we'll need a cache
		CachedLoader<Integer, Sprite> frameLoader = new CachedLoader<Integer, Sprite>() {
			@Override
			protected Sprite populatePool(Integer k) {
				return LargeImageFrameLoader.load(TTResource.spriteFrame(spriteName, k));
			}};

		DataItem diRoot = sdp.load(spriteName);
		for (DataItem diAnim : diRoot.requireField("anims").requireList()) {
			DataItem[] diFrames = diAnim.requireField("frames").requireList();
			Sprite[] frames = new Sprite[diFrames.length];
			for (int x = 0; x < frames.length; x++) {
				int fno = diFrames[x].requireInt();
				frames[x] = frameLoader.load(fno);;
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
		return new SpriteSet(an);
	}

}
