package com.nney.tt.resources;

import com.nney.json.DataItem;
import com.nney.json.JsonException;
import com.nney.json.JsonValue;
import com.nney.utils.ClassResourceOpenable;
import com.nney.utils.FileOpenable;
import com.nney.utils.Openable;
import com.nney.utils.StringIO;

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
		return TTResource.formatted("config/%s", name);
	}

	public static Openable legacyMap(String fn) {
		String filename = String.format("C:/Users/david/Desktop/newdata/maps/%s", fn);
		return new FileOpenable(filename);
	}

	public static Openable spriteFrame(String spriteName, int frameNumber) {
		return TTResource.formatted("anims/%s/%03d.png", spriteName, frameNumber);
	}

	public static Openable spriteDef(String spriteName) {
		return TTResource.formatted("anims/%s/def.txt", spriteName);
	}
	
	public static Openable music(String s) {
		return TTResource.formatted("sounds/music/%s", s);
	}

	public static Openable horizon(int name) {
		return TTResource.formatted("horizons/%d.png", name);
	}

	
	
	
	public static DataItem diFromText(Openable o) {
		try {
			String t = StringIO.mustLoadText(o, null);
			return JsonValue.parse(t);
		}
		catch (JsonException e) {
			throw new RuntimeException(e);
		}
	}

}
