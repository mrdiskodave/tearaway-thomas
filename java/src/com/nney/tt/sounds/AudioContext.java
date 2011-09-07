package com.nney.tt.sounds;

public interface AudioContext {
	
	Sound createStereoSound(short[] data);
	Sound createMonoSound(byte[] data);
	
	void startMusic(float vol, Loop music);
	void setMusicVolume(float vol);
	
	void loadEffect(float vol, Sound sound);
	void playEffect(int x);
}
