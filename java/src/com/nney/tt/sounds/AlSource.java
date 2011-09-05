package com.nney.tt.sounds;

import org.lwjgl.openal.AL10;

import com.nney.tt.gfx.Disposable;

public class AlSource implements Disposable {
	final int name;

	AlSource() {
		// Bind the buffer with the source.
		name = AlTools.alCheckName(AL10.alGenSources());
		AL10.alSourcef(name, AL10.AL_PITCH, 1.0f);
		AL10.alSourcef(name, AL10.AL_GAIN, 1.0f);
		AL10.alSource(name, AL10.AL_POSITION, AlTools.ORIGIN);
		AL10.alSource(name, AL10.AL_VELOCITY, AlTools.ORIGIN);
		AlTools.alCheck();
	}
	
//	void attach(AlBuffer buffer) {
//		AL10.alSourcei(name, AL10.AL_BUFFER, buffer.name);
//	}

	@Override
	public void dispose() {
		AL10.alDeleteSources(name);
	}

	public int state() {
		return AL10.alGetSourcei(name, AL10.AL_SOURCE_STATE);
	}

	public int buffersProcessed() {
		return AL10.alGetSourcei(name, AL10.AL_BUFFERS_PROCESSED);
	}

	public void queue(AlBuffer buffer) {
		AL10.alSourceQueueBuffers(name, buffer.name);		
	}

	public void play() {
		AL10.alSourcePlay(name);
	}

	public void unqueue() {
		AL10.alSourceUnqueueBuffers(name);		
	}

}
