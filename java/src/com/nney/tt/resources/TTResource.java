package com.nney.tt.resources;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.text.SimpleDateFormat;
import java.util.Date;

import com.nney.datanode.Node;
import com.nney.json.JsonParser;
import com.nney.utils.ClassResourceOpenable;
import com.nney.utils.FileOpenable;
import com.nney.utils.Openable;
import com.nney.utils.StringIO;

/**
 * All the knowledge about how to open our external resources.
 */
public class TTResource {
	private static final String FORMAT_FOR_MAP_PATH = "maps/%s.txt";
	private static final String FORMAT_FOR_SCRIPT_PATH = "scripts/%s.txt";
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
		return plain(String.format(format, args));
	}

	public static Openable plain(String formattedName) {
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

	public static Openable script(String name) {
		return TTResource.formatted(FORMAT_FOR_SCRIPT_PATH, name);
	}

	public static void saveScript(String name, String content) {
		String formattedName = String.format(FORMAT_FOR_SCRIPT_PATH, name);
		saveResource(formattedName, content, false);
	}

	public static Openable map(String name) {
		return TTResource.formatted(FORMAT_FOR_MAP_PATH, name);
	}

	public static void saveMap(String name, String content, boolean autoSave) {
		String formattedName = String.format(FORMAT_FOR_MAP_PATH, name);
		saveResource(formattedName, content, autoSave);
	}

	private static void saveResource(String formattedName, String content, boolean autoSave) {
		requireResourcePath();
		File f = new File(resourcePath, formattedName);
		try {
			if (autoSave) {
				f = uniqueName("autosave", f);
			}
			else {
				if (f.exists()) {
					File dest = uniqueName("backup", f);
					System.out.println(f + " renamed to " + dest);
					f.renameTo(dest);
				}
			}

			System.out.println("Saving to resource path: " + f);
			FileOutputStream fos = new FileOutputStream(f);
			try {
				// ISO-8859-1 AKA Latin-1
				Writer w = new OutputStreamWriter(fos, "ISO-8859-1");
				w.write(content);
				w.flush();
				w.close();
			}
			finally {
				fos.close();
			}

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

	public static boolean animExists(String spriteName) {
		assert spriteName != null;
		return animDef(spriteName) != null || openableExists(bareSprite(spriteName));
	}

	public static Openable animDef(String spriteName) {
		Openable answer = TTResource.formatted("anims/%s/def.txt", spriteName);
		if (!openableExists(answer)) return null;
		return answer;
	}

	public static Openable bareSprite(String spriteName) {
		return TTResource.formatted("anims/%s.png", spriteName);
	}

	public static Openable animSprite(String spriteName, int frameNumber) {
		return TTResource.formatted("anims/%s/%03d.png", spriteName, frameNumber);
	}

	public static boolean openableExists(Openable openable) {
		try {
			openable.open().close();
			return true;
		}
		catch (IOException e) {
			return false;
		}
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

	public static Node asNode(Openable o) {
		return asNode(asText(o));
	}

	public static Node asNode(String text) {
		return JsonParser.mustParse(text);
	}

	public static String asText(Openable o) {
		return StringIO.mustLoadText(o, null);
	}

}
