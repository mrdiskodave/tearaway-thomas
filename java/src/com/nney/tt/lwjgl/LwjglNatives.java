package com.nney.tt.lwjgl;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.Arrays;

/**
 * LWJGL needs native libraries. The build puts the Windows ones inside the jar
 * (natives/windows/); this unpacks them to a folder in the temp directory and
 * tells LWJGL to look there.
 */
final class LwjglNatives {
	private static final String[] NAMES = { "lwjgl.dll", "lwjgl64.dll", "OpenAL32.dll", "OpenAL64.dll" };

	private LwjglNatives() {
	}

	static void prepare() {
		if (!System.getProperty("os.name", "").toLowerCase().startsWith("windows")) {
			throw new IllegalStateException(
					"The LWJGL front end only has Windows libraries. Leave out --lwjgl to use the Java2D one.");
		}
		if (LwjglNatives.class.getResource("/natives/windows/" + NAMES[0]) == null) {
			// not running from the jar (e.g. from Eclipse): rely on java.library.path
			return;
		}
		File dir = new File(System.getProperty("java.io.tmpdir"), "tearaway-thomas-lwjgl");
		try {
			Files.createDirectories(dir.toPath());
			for (String n : NAMES) {
				byte[] want;
				try (InputStream in = LwjglNatives.class.getResourceAsStream("/natives/windows/" + n)) {
					if (in == null) throw new IllegalStateException("The jar is missing natives/windows/" + n);
					want = in.readAllBytes();
				}
				File f = new File(dir, n);
				// leave it alone if it's already right (it may be in use by another copy of the game)
				if (f.exists() && Arrays.equals(Files.readAllBytes(f.toPath()), want)) continue;
				Files.write(f.toPath(), want);
			}
		}
		catch (IOException e) {
			throw new RuntimeException("Couldn't unpack the LWJGL libraries to " + dir, e);
		}
		System.setProperty("org.lwjgl.librarypath", dir.getAbsolutePath());
	}
}
