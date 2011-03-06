package com.nney;

import java.util.List;

public class FrameGetter {
	private final FrameLoader loader;
	private final FrameRenderer render;

	FrameGetter(FrameLoader loader, FrameRenderer render) {
		this.loader = loader;
		this.render = render;
	}
	
	Bob[] get(List<Frame> frames) {
		Frame[] framea = (Frame[]) frames.toArray(new Frame[frames.size()]);
		Bob[] bobs = new Bob[framea.length];
		for (int x=0; x<framea.length; x++) {
			byte[] data = loader.load(framea[x]);
			bobs[x] = render.render(data);
		}
		return bobs;
	}
}
