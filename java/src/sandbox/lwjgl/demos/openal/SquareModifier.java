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
			byte v = LEFT_SQUARE;
			wll(x, v);
		}

		this.sqrPos = sqrBegin;
		this.sqrRight = true;
		this.sqrBegin = sqrBegin;
		this.sqrEnd = sqrEnd;

	}

	private void wll(int x, byte v) {
		if (x<localLoop.length) localLoop[x] = v;
	}

	void modify() {
		if (sqrRight) {
			wll(sqrPos, RIGHT_SQUARE);
			if (sqrPos == sqrEnd) {
				sqrRight = false;
			}
			else {
				sqrPos++;
			}
		}
		else {
			wll(sqrPos, LEFT_SQUARE);
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
