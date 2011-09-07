package com.nney.tt.lwjgl;

import java.util.ArrayList;

import com.nney.tt.gfx.Disposable;
import com.nney.tt.sounds.AudioContext;
import com.nney.tt.sounds.Loop;
import com.nney.tt.sounds.Sound;

public class AlAudioContext implements AudioContext, Disposable {
	private static final int SIMULTANEOUS_FX = 1;

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
	
	private ArrayList<AlSource> fxPlaying = new ArrayList<AlSource>();

	public AlAudioContext() {
		AlTools.alInit();
	}
	
	@Override
	public void startMusic(float vol, Loop music) {
		stopMusic();
		
		musicSource = new AlSource();
		musicSource.setVol(vol);
		musicStart = new AlBuffer(music.begin);
		if (music.loop!=null) {
			musicLoop = new AlBuffer(music.loop);
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
	public void loadEffect(float vol, Sound sound) {
		fxs.add(new FX(new AlBuffer(sound), vol));
	}

	@Override
	synchronized public void playEffect(int x) {
		FX f = fxs.get(x);
		
		AlSource s = new AlSource();
		s.setVol(f.vol);
		s.attach(f.buffer);
		s.play();
		
		fxPlaying.add(s);
		while (fxPlaying.size()>SIMULTANEOUS_FX) {
			stripFx();
		}
	}

	private void stripFx() {
		fxPlaying.remove(0).dispose();
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
		while (fxPlaying.size()!=0) {
			stripFx();
		}
		for (FX fx: fxs) {
			fx.buffer.dispose();
		}
		AlTools.alShutdown();
	}

	@Override
	public Sound createStereoSound(short[] data) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Sound createMonoSound(byte[] data) {
		// TODO Auto-generated method stub
		return null;
	}
}
