package com.nney.tt.lwjgl;

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

	void attach(AlBuffer buffer) {
		AL10.alSourcei(name, AL10.AL_BUFFER, buffer.name);
	}

	@Override
	public void close() {
		AL10.alDeleteSources(name);
		AlTools.alCheck();
	}

	public int state() {
		int answer = AL10.alGetSourcei(name, AL10.AL_SOURCE_STATE);
		AlTools.alCheck();
		return answer;
	}

	public int buffersProcessed() {
		int answer = AL10.alGetSourcei(name, AL10.AL_BUFFERS_PROCESSED);
		AlTools.alCheck();
		return answer;
	}

	public void queue(AlBuffer buffer) {
		AL10.alSourceQueueBuffers(name, buffer.name);
		AlTools.alCheck();
	}

	public void play() {
		AL10.alSourcePlay(name);
		AlTools.alCheck();
	}

	public void unqueue() {
		AL10.alSourceUnqueueBuffers(name);
		AlTools.alCheck();
	}

	public void setVol(float vol) {
		AL10.alSourcef(name, AL10.AL_GAIN, vol);
	}
}
