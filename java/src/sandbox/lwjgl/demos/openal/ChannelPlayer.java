package sandbox.lwjgl.demos.openal;

public class ChannelPlayer {
	private final ChannelController target;
	private final Lesson1 srv;

	ChannelPlayer(ChannelController target, Lesson1 srv) {
		this.target = target;
		this.srv = srv;
	}
	
	void play(int n, int i, int ap) {
		Instr instr = srv.findInstr(i);
		
		int param = ap&15;
		int action = ap>>4;
		if (action!=0) {
			
			// 1: Portamento
			// 2: asdr rate
			// 3: Arpeggiation
			// 4: double tap

			status("unimplemented action: "+action+" param"+param);
		}
		
		if (n==0) {
			
		}
		else if (n==1) {
			target.stop();
		}
		else if (n==2) {
			target.release();
		}
		else {
			// -2? means the lowest note can't be played?
			target.startNote(instr, n-2);
		}
	}
	
	private void status(String string) {
		System.out.println(string);
	}
}
