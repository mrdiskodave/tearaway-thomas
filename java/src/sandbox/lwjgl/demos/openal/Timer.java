package sandbox.lwjgl.demos.openal;

public class Timer {
	int value;
	int reset;
	
	boolean action() {
		if (value==0) return false;
		value--;
		if (value!=0) return false;
		value = reset;
		return true;
	}
	
	void init(int r) {
		value = reset = r;
	}
}
