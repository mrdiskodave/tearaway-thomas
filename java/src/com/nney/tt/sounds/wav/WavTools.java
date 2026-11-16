package com.nney.tt.sounds.wav;

import com.nney.tt.resources.TTResource;
import com.nney.tt.sounds.Sound;
import com.nney.tt.sounds.SoundTools;
import com.nney.tt.sounds.music.DataSrc;
import com.nney.utils.OpenableTools;

public class WavTools {
	static class BadWavFile extends RuntimeException {
		private static final long serialVersionUID = 1L;

		public BadWavFile(String message) {
			super(message);
		}

		public BadWavFile() {
			super();
		}

		public BadWavFile(String message, Throwable cause) {
			super(message, cause);
		}

		public BadWavFile(Throwable cause) {
			super(cause);
		}

	}

	public static Sound read(byte[] data) {
		// https://ccrma.stanford.edu/courses/422/projects/WaveFormat/
		int channels = -1;
		int bitsPerSample = -1;
		int sampleRate = -1;

		DataSrc d = new DataSrc(data);
		if (d.fourCharacterCode(0).equals("RIFF")) {
			if (d.fourCharacterCode(8).equals("WAVE")) {
				DataSrc f = d.subDataSrc(12, d.unsignedLongLE(4) - 4);
				while (f.length() != 0) {
					String name = f.fourCharacterCode(0);
					int length = f.unsignedLongLE(4);
					DataSrc content = f.subDataSrc(8, length);
					if (name.equals("fmt ")) {
						int format = content.unsignedWordLE(0);
						channels = content.unsignedWordLE(2);
						sampleRate = content.unsignedLongLE(4);
						bitsPerSample = content.unsignedWordLE(14);
						if (format != 1) throw new BadWavFile("Need 'fmt':format of 1 but got " + format);
					}
					if (name.equals("data")) {
						if (bitsPerSample == -1) {
							throw new BadWavFile("Bad ordering: 'fmt' before 'data'");
						}
						if (bitsPerSample % 8 != 0) {
							throw new BadWavFile("Sample must be a whole number of bytes");
						}

						if (bitsPerSample != 8 || channels != 1) {
							throw new BadWavFile("We only take mono 8bit WAV data for sound effects: this is "
									+ bitsPerSample + "bit " + channels + "channel");
						}

						byte[] raw = content.rawData(0, content.length());
						short[] answer = SoundTools.upscaleMono(SoundTools.upscaleUnsigned8(raw));
						return new Sound(answer, sampleRate);
					}
					f = f.subDataSrc(8 + length + (length & 1));
				}
			}
		}
		throw new BadWavFile("We never saw a 'data' chunk");
	}

	public static void main(String[] args) {
		byte[] data = OpenableTools.mustLoad(TTResource.fx("fxgem.wav"));
		read(data);
	}
}
