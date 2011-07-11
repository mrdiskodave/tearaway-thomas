package sandbox.lwjgl.demos.openal;

public class SquareModifier {
	static final byte RIGHT_SQUARE = -64;
	static final byte LEFT_SQUARE = 63;
	private byte[] localLoop;
	private final int sqrBegin;
	private final int sqrEnd;
	private int sqrPos;
	private boolean sqrRight;

	public SquareModifier(byte[] loop, int sqrBegin, int sqrEnd, boolean goRight) {
		localLoop = loop.clone();
		for (int x = sqrBegin; x <= sqrEnd; x++) {
			byte v = LEFT_SQUARE;
			safePoke(x, v);
		}

		this.sqrPos = sqrBegin;
		this.sqrRight = goRight;
		this.sqrBegin = sqrBegin;
		this.sqrEnd = sqrEnd;

	}

	private void safePoke(int offset, byte value) {
		if (offset<localLoop.length) localLoop[offset] = value;
	}

	void modify() {
		if (sqrRight) {
			safePoke(sqrPos, RIGHT_SQUARE);
			if (sqrPos == sqrEnd) {
				sqrRight = false;
			}
			else {
				sqrPos++;
			}
		}
		else {
			safePoke(sqrPos, LEFT_SQUARE);
			if (sqrPos == sqrBegin) {
				sqrRight = true;
			}
			else {
				sqrPos--;
			}
		}
//		System.out.println(DebugTools.showBin(localLoop));
	}
	
	byte[] read() {
		return localLoop;
	}
}
