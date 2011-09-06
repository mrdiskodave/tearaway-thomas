package com.nney.tt.sounds;

public interface AudioContext {
	void startMusic(float vol, int freq, Loop music);
	void setMusicVolume(float vol);
	
	void loadEffect(float vol, int freq, Sound sound);
	void playEffect(int x);
}
