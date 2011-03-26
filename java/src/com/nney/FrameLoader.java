package com.nney;

public abstract class FrameLoader {
	public abstract Sprite load(SpriteName f);
	
	void loadAll(Anim... anims) {
		for (Anim anim: anims) {
			for (SpriteName spriteName: anim.bobs){
				load(spriteName);
			}
		}
	}
}