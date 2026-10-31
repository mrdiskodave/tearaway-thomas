package com.nney.tt.lwjgl;

import java.nio.FloatBuffer;

import org.lwjgl.BufferUtils;
import org.lwjgl.LWJGLException;
import org.lwjgl.openal.AL;
import org.lwjgl.openal.AL10;

public class AlTools {
	public static final FloatBuffer ORIGIN = createFloatBuffer(0.0f, 0.0f, 0.0f);

	public static FloatBuffer createFloatBuffer(float... f) {
		FloatBuffer b = BufferUtils.createFloatBuffer(f.length);
		b.put(f);
		b.rewind();
		return b;
	}

	static int alCheckName(int name) {
		if (name <= 0) {
			throw new RuntimeException("Bad OpenAL name returned: " + name);
		}
		alCheck();
		return name;
	}

	/** All the devices OpenAL can play to. (AL must be created.) */
	static java.util.List<String> devices() {
		String all = org.lwjgl.openal.ALC10.alcIsExtensionPresent(null, "ALC_ENUMERATE_ALL_EXT")
				? org.lwjgl.openal.ALC10.alcGetString(null, org.lwjgl.openal.ALC11.ALC_ALL_DEVICES_SPECIFIER)
				: org.lwjgl.openal.ALC10.alcGetString(null, org.lwjgl.openal.ALC10.ALC_DEVICE_SPECIFIER);
		java.util.List<String> answer = new java.util.ArrayList<String>();
		if (all != null) {
			for (String s : all.split("\u0000")) {
				if (!s.isEmpty()) answer.add(s);
			}
		}
		return answer;
	}

	/**
	 * The full name of the first device whose name has this in it (ignoring
	 * case), or null (none asked for, or none matches: then say so).
	 */
	static String findDevice(String text) {
		if (text == null) return null;
		for (String d : devices()) {
			if (d.toLowerCase().contains(text.toLowerCase())) return d;
		}
		System.out.println("No sound device has \"" + text + "\" in its name; using the default");
		return null;
	}

	static void alCheck() {
		int e = AL10.alGetError();
		if (e != AL10.AL_NO_ERROR) {
			throw new RuntimeException("Unrecoverable OpenAL error code: " + e);
		}
	}

	/**
	 * @param deviceText
	 *            Part of the name of the sound device to use (as --beep lists
	 *            them), or null for the default.
	 */
	public static void alInit(String deviceText) {
		try {
			AL.create();
			String want = findDevice(deviceText);
			if (want != null) {
				AL.destroy();
				AL.create(want, 44100, 60, false);
			}
			System.out.println("Sound: " + org.lwjgl.openal.ALC10.alcGetString(AL.getDevice(),
					org.lwjgl.openal.ALC10.ALC_DEVICE_SPECIFIER));
			AL10.alGetError();
		}
		catch (LWJGLException le) {
			throw new RuntimeException(le);
		}
		alCheck();

		// Set Listener Position
		AL10.alListener(AL10.AL_POSITION, AlTools.ORIGIN);
		AL10.alListener(AL10.AL_VELOCITY, AlTools.ORIGIN);

		// first 3 elements are "at"
		// second 3 are "up"
		FloatBuffer orientation = AlTools.createFloatBuffer(0.0f, 0.0f, -1.0f, 0.0f, 1.0f, 0.0f);
		AL10.alListener(AL10.AL_ORIENTATION, orientation);
	}

	/**
	 * We have allocated memory for our buffers and sources which needs to be
	 * returned to the system. This function frees that memory.
	 */
	public static void alShutdown() {
		AL.destroy();
	}

}
