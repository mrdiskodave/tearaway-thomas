package sandbox.lwjgl.demos.openal;

public class Counter {
	int current;
	int max;
	
	boolean inc() {
		current++;
		return current==max;
	}
}
