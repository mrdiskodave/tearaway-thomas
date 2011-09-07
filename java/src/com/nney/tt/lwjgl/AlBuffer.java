package com.nney.tt.lwjgl;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.ShortBuffer;

import org.lwjgl.BufferUtils;
import org.lwjgl.openal.AL10;

import com.nney.tt.gfx.Disposable;
import com.nney.tt.sounds.Sound;

public class AlBuffer implements Disposable {
	final int name;

	public AlBuffer(Sound sound) {
		short[] data = sound.data;
		ByteBuffer bb = BufferUtils.createByteBuffer(data.length * 2);
		bb.order(ByteOrder.nativeOrder());
		ShortBuffer sb = bb.asShortBuffer();
		for (int x = 0; x < data.length; x++) {
			sb.put((short) data[x]);
		}
		int buffer = AlTools.alCheckName(AL10.alGenBuffers());
		AL10.alBufferData(buffer, AL10.AL_FORMAT_STEREO16, bb, sound.freq());
		AlTools.alCheck();
		name = buffer;
		
		assert name!=0;
	}

	@Override
	public void dispose() {
		AL10.alDeleteBuffers(name);
		AlTools.alCheck();
	}
}
