package com.nney.tt.lwjgl;

import java.util.ArrayList;

import com.nney.tt.gfx.Disposable;
import com.nney.tt.sounds.AudioContext;
import com.nney.tt.sounds.Loop;
import com.nney.tt.sounds.Sound;

public class AlAudioContext implements AudioContext, Disposable {
	private static final int SIMULTANEOUS_FX = 1;

	class Effect implements Disposable {
		final AlBuffer buffer;
		final float vol;

		public Effect(AlBuffer buffer, float vol) {
			this.buffer = buffer;
			this.vol = vol;
		}

		@Override
		public void close() {
			buffer.close();
		}
	}

	class Music implements Disposable {
		public AlBuffer begin;
		public AlBuffer loop;

		Music(Loop content) {
			begin = new AlBuffer(content.begin);
			if (content.hasLoop()) {
				loop = new AlBuffer(content.loop);
			}
		}

		boolean hasLoop() {
			return loop != null;
		}

		@Override
		public void close() {
			begin.close();
			if (hasLoop()) {
				loop.close();
			}
		}
	}

	private AlSource musicSource;

	private float musicVol = 1;

	private Music[] musics = new Music[SLOTS];

	private ArrayList<Effect> effects = new ArrayList<>();

	private ArrayList<AlSource> effectPlaying = new ArrayList<>();

	private Music playing;

	/** @param deviceText part of the sound device's name, or null for the default */
	public AlAudioContext(String deviceText) {
		AlTools.alInit(deviceText);
	}

	@Override
	public void loadMusic(int slot, Loop loop) {
		stopMusic();
		freeMusic(slot);
		musics[slot] = new Music(loop);
	}

	private void freeMusic(int slot) {
		if (musics[slot] != null) {
			musics[slot].close();
		}
	}

	@Override
	public void startMusic(int slot) {
		stopMusic();

		playing = musics[slot];
		if (playing == null) {
			throw new IllegalStateException("Slot " + slot + " is empty");
		}
		System.out.println("starting begin " + musicVol);
		musicSource = new AlSource();
		musicSource.setVol(musicVol);
		musicSource.queue(playing.begin);
		if (playing.hasLoop()) musicSource.queue(playing.loop);
		musicSource.play();
	}

	@Override
	public void stopMusic() {
		if (musicSource == null) return;
		musicSource.setVol(0);
		musicSource.close();
		musicSource = null;
		playing = null;
	}

	@Override
	public void setMusicVolume(float vol) {
		musicVol = vol;
		musicSource.setVol(vol);
	}

	@Override
	public void loadEffect(float vol, Sound sound) {
		effects.add(new Effect(new AlBuffer(sound), vol));
	}

	@Override
	public void playEffect(int n) {
		Effect f = effects.get(n);

		AlSource s = new AlSource();
		s.setVol(f.vol);
		s.attach(f.buffer);
		s.play();

		effectPlaying.add(s);
		while (effectPlaying.size() > SIMULTANEOUS_FX) {
			stopEffect();
		}
	}

	private void stopEffect() {
		effectPlaying.remove(0).close();
	}

	public void update() {
		if (playing != null && playing.hasLoop()) {
			for (int x = 0; x < musicSource.buffersProcessed(); x++) {
				musicSource.unqueue();
				System.out.println("Q");
				musicSource.queue(playing.loop);
			}
		}
	}

	@Override
	public void close() {
		stopMusic();
		// dispose of musics
		for (int x = 0; x < SLOTS; x++) {
			freeMusic(x);
		}

		// stop effects
		while (effectPlaying.size() != 0) {
			stopEffect();
		}
		// dispose of effects
		for (Effect effect : effects) {
			effect.close();
		}

		AlTools.alShutdown();
	}
}
