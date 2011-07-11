package sandbox.lwjgl.demos.openal;

public class Timer {
	private int value;
	private int reset;
	
	boolean isTime() {
		if (reset==0) return false;
		if (value==0) {
			value = reset;
			return true;
		}
		value--;
		return false;
	}
	
	void every(int r) {
		value = reset = r;
	}

	public void everyAndNow(int r) {
		reset = r;
		value = 0;
	}

	public void nextTime() {
		value = 0;
	}
}
