package com.nney.tt.tools;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

import com.nney.datanode.DataDestination;
import com.nney.json.IndentedJsonFormatter;
import com.nney.json.JsonDataDestination;
import com.nney.json.SafeWriter;
import com.nney.json.StringSafeWriter;
import com.nney.tt.AlienFactory;
import com.nney.tt.AlienInfoMap;
import com.nney.tt.LevelInfo;
import com.nney.tt.PersistedLevel;
import com.nney.tt.aliens.Alien;
import com.nney.tt.aliens.LegacyAlien;
import com.nney.tt.props.OPS;
import com.nney.tt.resources.TTResource;

/**
 * Developer tool: upgrades the level files in resources/maps as aliens get
 * ported.
 *
 * Levels still hold some objects as raw Amiga data ("legacy" objects). The game
 * upgrades them as it loads (see {@link AlienFactory#upgrade}) once a Java class
 * exists for their type, but it's nicer to have them in the files properly so
 * the map editor shows their real properties.
 *
 * This edits each such object in place and leaves the rest of the file
 * untouched (the files come in two slightly different formats and re-saving a
 * whole level would rewrite thousands of lines).
 *
 * <pre>
 * MapTool check   RESOURCES_DIR    say what would change
 * MapTool upgrade RESOURCES_DIR    change it
 * </pre>
 */
public class MapTool {
	public static void main(String[] args) throws Exception {
		boolean write = args[0].equals("upgrade");
		File res = new File(args[1]);
		TTResource.setResourcePath(res);
		int total = 0;
		for (int i = 0; i < PersistedLevel.levelCount(); i++) {
			PersistedLevel pl = new PersistedLevel(i, null);
			LevelInfo li = pl.getLevelInfo();
			AlienFactory af = new AlienFactory(new AlienInfoMap(li.worldName, null));

			File f = new File(res, "maps/" + pl.getMapName() + ".txt");
			String text = new String(Files.readAllBytes(f.toPath()), StandardCharsets.ISO_8859_1);
			boolean crlf = text.contains("\r\n");
			boolean spaceAfterComma = text.contains(", \n") || text.contains(", \r\n");

			List<String> done = new ArrayList<String>();
			for (Alien a : pl.getAliens(new AlienFactory(new AlienInfoMap(li.worldName, null)) {
				// load without upgrading so we can see the legacy ones
				@Override
				public Alien upgrade(LegacyAlien legacy) {
					return legacy;
				}
			})) {
				if (!(a instanceof LegacyAlien)) continue;
				LegacyAlien legacy = (LegacyAlien) a;
				Alien upgraded = af.upgrade(legacy);
				if (upgraded == legacy) continue;
				if (upgraded == null) {
					// merged into an alien made from an earlier one
					text = removeObject(text, legacy.data);
					done.add("(merged)");
					continue;
				}

				String json = serialise(upgraded);
				text = replaceObject(text, legacy.data, json, crlf, spaceAfterComma);
				done.add(upgraded.alienInfo.name);
			}
			if (!done.isEmpty()) {
				total += done.size();
				System.out.println(pl.getMapName() + ": " + done.size() + " upgraded " + done);
				if (write) Files.write(f.toPath(), text.getBytes(StandardCharsets.ISO_8859_1));
			}
		}
		System.out.println(total + " legacy object(s) " + (write ? "upgraded" : "would be upgraded"));
	}

	/** One alien as JSON, the way PersistedLevel saves them. */
	static String serialise(Alien a) {
		SafeWriter sw = new StringSafeWriter();
		IndentedJsonFormatter ijf = new IndentedJsonFormatter(sw);
		ijf.spaciousSeperators();
		DataDestination dd = new JsonDataDestination(ijf);
		dd.beginObject();
		dd.write("type");
		dd.write(a.alienInfo.name);
		OPS.saveProps(a, dd);
		dd.end();
		return sw.toString();
	}

	/** Delete the object holding the given legacy data, and its comma. */
	static String removeObject(String text, String legacyHex) {
		int at = text.indexOf("\"" + legacyHex + "\"");
		if (at < 0) throw new RuntimeException("Can't find legacy object " + legacyHex);
		int start = text.lastIndexOf('{', at);
		int end = text.indexOf('}', at) + 1;
		int lineStart = text.lastIndexOf('\n', start) + 1;
		// "{...}," then whitespace up to the next object: take all of it
		int after = end;
		while (after < text.length() && (text.charAt(after) == ' ' || text.charAt(after) == '\t')) after++;
		if (after < text.length() && text.charAt(after) == ',') {
			after++;
			while (after < text.length() && text.charAt(after) != '\n') after++;
			return text.substring(0, lineStart) + text.substring(after + 1);
		}
		// last in the list: take the comma off the one before instead
		// ("...},<newline>{us}<newline>]" becomes "...}<newline>]")
		int comma = text.lastIndexOf(',', start);
		return text.substring(0, comma) + text.substring(end);
	}

	/**
	 * Find the object holding the given legacy data and swap in the new JSON,
	 * indented and punctuated to match its surroundings.
	 */
	static String replaceObject(String text, String legacyHex, String json, boolean crlf, boolean spaceAfterComma) {
		int at = text.indexOf("\"" + legacyHex + "\"");
		if (at < 0) throw new RuntimeException("Can't find legacy object " + legacyHex);
		int start = text.lastIndexOf('{', at);
		int end = text.indexOf('}', at) + 1;

		// indentation of the line the object starts on
		int lineStart = text.lastIndexOf('\n', start) + 1;
		String indent = text.substring(lineStart, start);

		String nl = crlf ? "\r\n" : "\n";
		StringBuilder sb = new StringBuilder();
		String[] lines = json.replace("\r\n", "\n").split("\n");
		for (int i = 0; i < lines.length; i++) {
			String line = lines[i];
			if (spaceAfterComma && line.endsWith(",")) line += " ";
			if (i != 0) sb.append(nl).append(indent);
			sb.append(line);
		}
		return text.substring(0, start) + sb + text.substring(end);
	}
}
