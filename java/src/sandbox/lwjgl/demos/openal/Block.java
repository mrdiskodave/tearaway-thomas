package sandbox.lwjgl.demos.openal;

public class Block {
	public final byte[] data;
	public final int lines;

	Block(Song song, int number) {
		data = song.block(number);
		assert data.length % 12 == 0;
		lines = data.length / 12;
	}
	
	int lineOffset(int line) {
		return line * 12;
	}
}
