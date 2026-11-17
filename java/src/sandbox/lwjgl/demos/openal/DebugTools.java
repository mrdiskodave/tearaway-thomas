package sandbox.lwjgl.demos.openal;

class DebugTools {
	static String showBin(byte[] b) {
		StringBuilder sb = new StringBuilder();
		for (int x = 0; x < b.length; x++) {
			sb.append(String.format("%02x", b[x]));
		}
		return sb.toString();
	}
}
