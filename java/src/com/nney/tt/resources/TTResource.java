package com.nney.tt.resources;

import com.nney.utils.ClassResourceOpenable;
import com.nney.utils.FileOpenable;
import com.nney.utils.Openable;

/**
 * All the knowledge about how to open our external resources. Some are still on
 * disk but we're headed towards getting them all into SVN!
 */
public class TTResource {
	private static Openable formatted(String format, Object... args) {
		return new ClassResourceOpenable(TTResource.class, String.format(format, args));
	}

	public static Openable blockDef(String worldName) {
		return TTResource.formatted("blocks/%sdef.txt", worldName);
	}

	public static Openable blockMask(String worldName) {
		return TTResource.formatted("blocks/%sm.png", worldName);
	}

	public static Openable blocks(String worldName) {
		return TTResource.formatted("blocks/%s.png", worldName);
	}

	public static Openable font(String name) {
		return TTResource.formatted("fonts/%s.png", name);
	}

	public static Openable config(String name) {
		return TTResource.formatted("config/%s.png", name);
	}

	public static Openable map(String world, int levelNumber) {
		String filename = String.format("C:/Users/david/Desktop/newdata/maps/%s%d.map", world, levelNumber);
		return new FileOpenable(filename);
	}

	public static Openable spriteFrame(String spriteName, int frameNumber) {
		String filename = String.format("C:/Users/david/Desktop/newdata/bobs/%s/%03d.png", spriteName, frameNumber);
		return new FileOpenable(filename);
	}

	public static Openable spriteDef(String spriteName) {
		String filename = String.format("C:/Users/david/Desktop/newdata/bobs/%s/def.txt", spriteName);
		return new FileOpenable(filename);
	}
	
	public static Openable horizon(int name) {
		String filename = String.format("C:/Users/david/Desktop/newdata/horizons/%d.png", name);
		return new FileOpenable(filename);
	}

}
