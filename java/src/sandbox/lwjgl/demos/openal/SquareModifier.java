package sandbox.lwjgl.demos.openal;

public class SquareModifier {
	static final byte RIGHT_SQUARE = -64;
	static final byte LEFT_SQUARE = 63;
	private byte[] localLoop;
	private final int sqrBegin;
	private final int sqrEnd;
	private int sqrPos;
	private boolean sqrRight;

	public SquareModifier(byte[] loop, int sqrBegin, int sqrEnd) {
		localLoop = loop.clone();
		for (int x = sqrBegin; x <= sqrEnd; x++) {
			localLoop[x] = LEFT_SQUARE;
		}

		this.sqrPos = sqrBegin;
		this.sqrRight = true;
		this.sqrBegin = sqrBegin;
		this.sqrEnd = sqrEnd;

	}

	void modify() {
		if (sqrRight) {
			localLoop[sqrPos] = RIGHT_SQUARE;
			if (sqrPos == sqrEnd) {
				sqrRight = false;
			}
			else {
				sqrPos++;
			}
		}
		else {
			localLoop[sqrPos] = LEFT_SQUARE;
			if (sqrPos == sqrBegin) {
				sqrRight = true;
			}
			else {
				sqrPos--;
			}
		}
		System.out.println(DebugTools.showBin(localLoop));
	}
	
	byte[] read() {
		return localLoop;
	}
}
