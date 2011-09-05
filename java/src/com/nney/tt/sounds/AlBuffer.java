package com.nney.tt.sounds;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.ShortBuffer;

import org.lwjgl.BufferUtils;
import org.lwjgl.openal.AL10;

import com.nney.tt.gfx.Disposable;

public class AlBuffer implements Disposable {
	final int name;

	public AlBuffer(short[] data, int rate) {
		ByteBuffer bb = BufferUtils.createByteBuffer(data.length * 2);
		bb.order(ByteOrder.nativeOrder());
		ShortBuffer sb = bb.asShortBuffer();
		for (int x = 0; x < data.length; x++) {
			sb.put((short) data[x]);
		}
		int buffer = AlTools.alCheckName(AL10.alGenBuffers());
		AL10.alBufferData(buffer, AL10.AL_FORMAT_STEREO16, bb, rate);
		
		name = buffer;
	}

	@Override
	public void dispose() {
		AL10.alDeleteBuffers(name);
	}
}
