package com.nney.tt.lwjgl;

import java.nio.ByteBuffer;

import org.lwjgl.BufferUtils;
import org.lwjgl.openal.AL;
import org.lwjgl.openal.AL10;
import org.lwjgl.openal.ALC10;
import org.lwjgl.openal.ALC11;
import org.lwjgl.openal.ALCdevice;

/**
 * A sound test: one second of 440Hz through OpenAL, with what OpenAL can see
 * and what goes wrong. (java -jar tearaway-thomas.jar --lwjgl --beep)
 */
final class AlBeep {
	private AlBeep() {
	}

	static void run(String deviceText) {
		try {
			LwjglNatives.prepare();
			AL.create();
			String want = AlTools.findDevice(deviceText);
			if (want != null) {
				AL.destroy();
				AL.create(want, 44100, 60, false);
			}
		}
		catch (Throwable e) {
			System.out.println("OpenAL couldn't start: " + e);
			return;
		}
		try {
			ALCdevice device = AL.getDevice();
			say("Using device", () -> ALC10.alcGetString(device, ALC10.ALC_DEVICE_SPECIFIER));
			say("Default device", () -> ALC10.alcGetString(null, ALC10.ALC_DEFAULT_DEVICE_SPECIFIER));
			say("All devices", () -> ALC10.alcIsExtensionPresent(null, "ALC_ENUMERATE_ALL_EXT")
					? ALC10.alcGetString(null, ALC11.ALC_ALL_DEVICES_SPECIFIER)
					: ALC10.alcGetString(null, ALC10.ALC_DEVICE_SPECIFIER));
			say("OpenAL", () -> AL10.alGetString(AL10.AL_VENDOR) + ", " + AL10.alGetString(AL10.AL_RENDERER) + ", "
					+ AL10.alGetString(AL10.AL_VERSION));

			int rate = 44100;
			ByteBuffer data = BufferUtils.createByteBuffer(rate * 2);
			for (int i = 0; i < rate; i++) {
				data.putShort((short) (Math.sin(2 * Math.PI * 440 * i / rate) * 16000));
			}
			data.flip();
			int buffer = AL10.alGenBuffers();
			AL10.alBufferData(buffer, AL10.AL_FORMAT_MONO16, data, rate);
			int source = AL10.alGenSources();
			AL10.alSourcei(source, AL10.AL_BUFFER, buffer);
			AL10.alSourcef(source, AL10.AL_GAIN, 1f);
			AL10.alListenerf(AL10.AL_GAIN, 1f);
			AL10.alSourcePlay(source);
			System.out.println("BEEP (one second)...");
			check("starting");
			long until = System.currentTimeMillis() + 3000;
			while (AL10.alGetSourcei(source, AL10.AL_SOURCE_STATE) == AL10.AL_PLAYING
					&& System.currentTimeMillis() < until) {
				Thread.sleep(20);
			}
			check("playing");
			System.out.println("Done. Did you hear it?");
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
		finally {
			AL.destroy();
		}
	}

	private interface Getter {
		String get();
	}

	private static void say(String what, Getter g) {
		String s;
		try {
			s = g.get();
			if (s != null) s = s.replace('\0', '|');
		}
		catch (Throwable e) {
			s = "(couldn't tell: " + e + ")";
		}
		System.out.println(what + ": " + s);
	}

	private static void check(String when) {
		int e = AL10.alGetError();
		if (e != AL10.AL_NO_ERROR) System.out.println("OpenAL error " + e + " while " + when);
	}
}
