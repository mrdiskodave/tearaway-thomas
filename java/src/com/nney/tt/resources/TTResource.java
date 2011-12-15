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
	static private File localResourcePath;

	static class Ref {
		private final boolean local;
		private final String path;

		private Ref(boolean local, String path) {
			this.local = local;
			this.path = path;
		}

		static Ref createf(String format, Object... args) {
			return create(String.format(format, args));
		}

		public static Ref create(String p) {
			return new Ref(localResourcePath != null && new File(localResourcePath, p).exists(), p);
		}

		Openable openable() {
			if (local) return new FileOpenable(local());
			return nonLocal();
		}

		private File local() {
			return new File(localResourcePath, path);
		}

		private ClassResourceOpenable nonLocal() {
			return new ClassResourceOpenable(TTResource.class, path);
		}

		public boolean exists() {
			if (local) return true;
			try {
				nonLocal().open().close();
				return true;
			}
			catch (IOException e) {
				return false;
			}
		}
	}

	/**
	 * This is used during development when we want to read resources from local
	 * disk rather than from our classpath.
	 * 
	 * @param localResourcePath
	 */
	static public void setResourcePath(File localResourcePath) {
		TTResource.localResourcePath = localResourcePath;
		requireLocalResourcePath();
	}

	private static Openable simple(String format, Object... args) {
		return Ref.createf(format, args).openable();
	}

	private static Ref bareSpriteRef(String spriteName) {
		return Ref.createf("anims/%s.png", spriteName);
	}

	private static String scriptPath(String name) {
		return String.format("scripts/%s.txt", name);
	}

	private static String mapPath(String name) {
		return String.format("maps/%s.txt", name);
	}

	private static void saveResource(String formattedName, String content, boolean autoSave) {
		requireLocalResourcePath();
		File f = new File(localResourcePath, formattedName);
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

	private static void requireLocalResourcePath() {
		if (localResourcePath == null) {
			throw new RuntimeException("Resource path not configured");
		}
		if (!localResourcePath.isDirectory()) {
			throw new RuntimeException("Resource path not a directory: " + localResourcePath);
		}
	}

	public static Openable blockDef(String worldName) {
		return simple("blocks/%sdef.txt", worldName);
	}

	public static Openable blockMask(String worldName) {
		return simple("blocks/%sm.png", worldName);
	}

	public static Openable blocks(String worldName) {
		return simple("blocks/%s.png", worldName);
	}

	public static Openable font(String name) {
		return simple("fonts/%s.png", name);
	}

	public static Openable config(String name) {
		return simple("config/%s", name);
	}

	public static Openable animSprite(String spriteName, int frameNumber) {
		return simple("anims/%s/%03d.png", spriteName, frameNumber);
	}

	public static Openable music(String s) {
		return simple("sounds/music/%s", s);
	}

	public static Openable fx(String s) {
		return simple("sounds/fx/%s", s);
	}

	public static Openable horizon(int name) {
		return simple("horizons/%d.png", name);
	}

	// public static Openable legacyMap(String name) {
	// String filename =
	// String.format("C:/Users/david/Desktop/newdata/maps/%s.map", name);
	// return new FileOpenable(filename);
	// }

	public static Openable script(String name) {
		return Ref.create(scriptPath(name)).openable();
	}

	public static void saveScript(String name, String content) {
		saveResource(scriptPath(name), content, false);
	}

	public static Openable map(String name) {
		return Ref.create(mapPath(name)).openable();
	}

	public static void saveMap(String name, String content, boolean autoSave) {
		saveResource(mapPath(name), content, autoSave);
	}

	public static boolean animExists(String spriteName) {
		assert spriteName != null;
		return animDef(spriteName) != null || bareSpriteRef(spriteName).exists();
	}

	public static Openable animDef(String spriteName) {
		Ref answer = Ref.createf("anims/%s/def.txt", spriteName);
		if (!answer.exists()) return null;
		return answer.openable();
	}

	public static Openable bareSprite(String spriteName) {
		return bareSpriteRef(spriteName).openable();
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
