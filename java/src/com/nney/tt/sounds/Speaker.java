package com.nney.tt.sounds;

import org.lwjgl.openal.AL10;

public class Speaker {
	private static final int FREQ = 44100;

	private void play() {
//		MusicPlayer mp = new MusicPlayer();
//		mp.loadSong("intro");
//		mp.generate(new MusicPlayer.FirstBlockSongSlice()).collect();
		
		
		AlBuffer buffer1 = new AlBuffer(genWave(100, 90), FREQ);
		AlSource source = new AlSource();

//		AL10.alSourcei(source.name, AL10.AL_BUFFER, buffer1.name);
		
		
		AL10.alSourceQueueBuffers(source.name, buffer1.name);
		AL10.alSourceQueueBuffers(source.name, buffer1.name);
		
		AL10.alSourcePlay(source.name);

		for (;;) {
			pause();
			for (int x=0; x<source.buffersProcessed(); x++) {
				AL10.alSourceUnqueueBuffers(source.name);
				AL10.alSourceQueueBuffers(source.name, buffer1.name);
			}
		}
//		source.dispose();
//		buffer1.dispose();
	}

	private void pause() {
		try {
			Thread.sleep(5);
		}
		catch (InterruptedException e) {
			// ignored
		}
	}
	
	private short[] genWave(int reps, int halfCycleLength) {
		halfCycleLength *= 2;
		short[] z = new short[halfCycleLength*2*reps];
		int c = 0x5000;
		int x = 0;
		for (int a=0; a<reps; a++) {
			for (int b=0; b<halfCycleLength; b++) {
				z[x++] = (short) c;
				z[x++] = (short) c;
			}
			c = -c;
		}
		return z;
	}

	public void execute() {
		AlTools.alInit();
		play();
		AlTools.alShutdown();
	}

	public static void main(String[] args) {
		new Speaker().execute();
	}
}
