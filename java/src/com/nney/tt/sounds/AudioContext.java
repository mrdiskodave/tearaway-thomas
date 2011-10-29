package com.nney.tt.sounds;

public interface AudioContext {
	void loadMusic(int slot, Loop music);
	void startMusic(int slot);
	void setMusicVolume(float vol);
	void stopMusic();
	
	void loadEffect(float vol, Sound sound);
	void playEffect(int x);

}
