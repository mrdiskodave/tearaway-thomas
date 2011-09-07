package com.nney.tt.sounds;

public interface AudioContext {
	
	void setMusicVolume(float vol);

	void loadMusic(int slot, Loop music);
	void startMusic(int slot);
	
	void loadEffect(float vol, Sound sound);
	void playEffect(int x);
}
