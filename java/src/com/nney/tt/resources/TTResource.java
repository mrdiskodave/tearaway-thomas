package com.nney.tt.resources;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;

import com.nney.json.DataItem;
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
	private static final String FORMAT_FOR_MAP_PATH = "maps/%s.txt";
	static private File resourcePath;

	/**
	 * This is used during development when we want to read resources from local
	 * disk rather than from our classpath.
	 * 
	 * @param resourcePath
	 */
	static public void setResourcePath(File resourcePath) {
		TTResource.resourcePath = resourcePath;
		requireResourcePath();
	}

	private static Openable formatted(String format, Object... args) {
		String formattedName = String.format(format, args);
		if (resourcePath != null) {
			File f = new File(resourcePath, formattedName);
			if (f.exists()) {
				System.out.println("Loading from resource path: " + f);
				return new FileOpenable(f);
			}
		}
		return new ClassResourceOpenable(TTResource.class, formattedName);
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

	// public static Openable legacyMap(String name) {
	// String filename =
	// String.format("C:/Users/david/Desktop/newdata/maps/%s.map", name);
	// return new FileOpenable(filename);
	// }

	public static void saveMap(String name, String content, boolean autoSave) {
		requireResourcePath();
		String formattedName = String.format(FORMAT_FOR_MAP_PATH, name);
		saveResource(formattedName, content, autoSave);
	}

	private static void saveResource(String formattedName, String content, boolean autoSave) {
		File f = new File(resourcePath, formattedName);
		try {
			if (autoSave) {
				f = uniqueName("autosave", f);
			}
			else {
				if (f.exists()) {
					File dest = uniqueName("backup", f);
					System.out.println(f+" renamed to "+dest);
					f.renameTo(dest);
				}
			}
			
			System.out.println("Saving to resource path: " + f);
			FileWriter w = new FileWriter(f);
			w.write(content);
			w.close();
		}
		catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	private static File uniqueName(String t, File f) {
		Date date = new Date();
		SimpleDateFormat formatter = new SimpleDateFormat("'d'yyyyMMdd_'t'HHmm"); // ss
		String textDate = formatter.format(date);
		int version = 0;
		File dest;
		do {
			dest = new File(f.getParentFile(), String.format("%s_%s_v%s_%s", t, textDate, version, f.getName()));
			version++;
		} while (dest.exists());
		return dest;
	}

	static void requireResourcePath() {
		if (resourcePath == null) {
			throw new RuntimeException("Resource path not configured");
		}
		if (!resourcePath.isDirectory()) {
			throw new RuntimeException("Resource path not a directory: " + resourcePath);
		}
	}

	public static Openable map(String name) {
		return TTResource.formatted(FORMAT_FOR_MAP_PATH, name);
	}

	public static Openable spriteFrame(String spriteName, int frameNumber) {
		return TTResource.formatted("anims/%s/%03d.png", spriteName, frameNumber);
	}

	public static boolean spriteExists(String spriteName) {
		try {
			spriteDef(spriteName).open().close();
			return true;
		}
		catch (IOException e) {
			return false;
		}
	}

	public static Openable spriteDef(String spriteName) {
		return TTResource.formatted("anims/%s/def.txt", spriteName);
	}

	public static Openable music(String s) {
		return TTResource.formatted("sounds/music/%s", s);
	}

	public static Openable fx(String s) {
		return TTResource.formatted("sounds/fx/%s", s);
	}

	public static Openable horizon(int name) {
		return TTResource.formatted("horizons/%d.png", name);
	}

	public static DataItem diFromText(Openable o) {
		return JsonValue.mustParse(StringIO.mustLoadText(o, null));
	}

}
