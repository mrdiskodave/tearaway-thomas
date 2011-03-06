package com.nney;

public class FrameHub {
	private final FrameFinder finder;
	private final FrameLoader loader;
	private final FrameRenderer render;

	/**
	 * The three orthogonal concerns of frame loading brought together under one roof.
	 * @param finder
	 * @param loader
	 * @param render
	 */
	FrameHub(FrameFinder finder, FrameLoader loader, FrameRenderer render) {
		this.finder = finder;
		this.loader = loader;
		this.render = render;
	}
	
	Bob[] getFrames(String descr) {
		Frame[] frames = finder.parse(descr);
		Bob[] bobs = new Bob[frames.length];
		for (int x=0; x<frames.length; x++) {
			byte[] data = loader.load(frames[x]);
			bobs[x] = render.render(data);
		}
		return bobs;
	}
}
