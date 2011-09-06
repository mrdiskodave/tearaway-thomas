package com.nney.tt.lwjgl;

import java.util.ArrayList;

import com.nney.tt.gfx.Disposable;
import com.nney.tt.sounds.AudioContext;
import com.nney.tt.sounds.Loop;
import com.nney.tt.sounds.Sound;

public class AlAudioContext implements AudioContext, Disposable {
	private static final int SIMULTANEOUS_FX = 5;

	class FX {
		final AlBuffer buffer;
		final float vol;

		public FX(AlBuffer buffer, float vol) {
			this.buffer = buffer;
			this.vol = vol;
		}
	}

	private AlSource musicSource;
	private AlBuffer musicStart;
	private AlBuffer musicLoop;
	
	private ArrayList<FX> fxs = new ArrayList<FX>();
	
	private ArrayList<AlSource> playing = new ArrayList<AlSource>();

	public AlAudioContext() {
		AlTools.alInit();
	}
	
	@Override
	public void startMusic(float vol, int freq, Loop music) {
		stopMusic();
		
		musicSource = new AlSource();
		musicSource.setVol(vol);
		musicStart = new AlBuffer(music.begin, freq);
		if (music.loop!=null) {
			musicLoop = new AlBuffer(music.loop, freq);
			musicSource.queue(musicStart);
			musicSource.queue(musicLoop);
		}
		else {
			musicSource.attach(musicStart);
		}
		musicSource.play();
	}

	private void stopMusic() {
		if (musicSource==null) return;
		musicSource.setVol(0);
		musicSource.dispose();
		musicSource = null;
		musicStart.dispose();
		musicStart = null;
		if (musicLoop!=null) {
			musicLoop.dispose();
			musicLoop= null;
		}
	}

	@Override
	public void setMusicVolume(float vol) {
		if (vol==0) {
			stopMusic();
		}
		else {
			musicSource.setVol(vol);
		}
	}
	
	@Override
	public void loadEffect(float vol, int freq, Sound sound) {
		fxs.add(new FX(new AlBuffer(sound, freq), vol));
	}

	@Override
	synchronized public void playEffect(int x) {
		FX f = fxs.get(x);
		
		AlSource s = new AlSource();
		s.setVol(f.vol);
		s.attach(f.buffer);
		s.play();
		
		playing.add(s);
		while (playing.size()>SIMULTANEOUS_FX) {
			stripFx();
		}
	}

	private void stripFx() {
		playing.remove(0).dispose();
	}

	public void update() {
		if (musicLoop!=null) {
			for (int x=0; x<musicSource.buffersProcessed(); x++) {
				musicSource.unqueue();
				musicSource.queue(musicLoop);
			}
		}
	}

	@Override
	public void dispose() {
		stopMusic();
		while (playing.size()!=0) {
			stripFx();
		}
		for (FX fx: fxs) {
			fx.buffer.dispose();
		}
		AlTools.alShutdown();
	}
}
