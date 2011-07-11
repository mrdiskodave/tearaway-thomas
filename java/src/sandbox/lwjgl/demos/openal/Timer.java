package sandbox.lwjgl.demos.openal;

public class Timer {
	int value;
	int reset;
	
	boolean isTime() {
		if (value==0) return false;
		value--;
		if (value!=0) return false;
		value = reset;
		return true;
	}
	
	void every(int r) {
		value = reset = r;
	}

	public void everyAndNow(int r) {
		reset = r;
		value = 1;
	}
}
