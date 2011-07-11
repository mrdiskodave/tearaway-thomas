package sandbox.lwjgl.demos.openal;

public class ChannelPlayer {
	private final AudioChannel c = new AudioChannel();
	private final ChannelController cc;
	private final Lesson1 srv;
	public final ChannelConfig config;

	ChannelPlayer(Lesson1 srv, ChannelConfig config) {
		this.srv = srv;
		this.config = config;
		this.cc = new ChannelController(c, config.position<50);
	}
	
	void play(int n, int i, int ap) {
		Instr instr = srv.findInstr(i);
		
		int param = ap&15;
		int action = ap>>4;
		if (action!=0) {
			status("unimplemented action: "+action+" param"+param);
		}
		
		if (n==0) {
			// do nothing
		}
		else if (n==1) {
			cc.stop();
		}
		else if (n==2) {
			cc.release();
		}
		else {
			// -2? bug! that means the lowest note can't be played!
			cc.startNote(instr, n-2);
		}
	}
	
	private void status(String string) {
		System.out.println(string);
	}

	public void update() {
		cc.update();
	}

	public int sample() {
		return c.sample();
	}
}
