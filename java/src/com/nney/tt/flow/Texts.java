package com.nney.tt.flow;

import java.util.List;

/**
 * The words on the title, ending and high score screens, in the game's text
 * markup (see com.nney.tt.osd.OsdParser). Taken from the original's text
 * tables in s195 (daveNnick_text, thanks1_text, comp1_text... hst_template).
 *
 * Colours: [c0] white, [c1] red, [c2] green, [c3] blue, [c4] yellow, [c5] cyan.
 * The font has lower case letters only.
 */
final class Texts {
	private Texts() {
	}

	static final String WRITTEN_BY = "[c5]written by[p]" //
			+ "[c0]david hanney[n]" //
			+ "[c4]and[n]" //
			+ "[c0]nick frampton";

	private static String thanks(String... names) {
		StringBuilder sb = new StringBuilder("[c5]thanks to[p]");
		for (int i = 0; i < names.length; i++) {
			if (i != 0) sb.append("[n]");
			sb.append("[c").append(i % 2 == 0 ? 0 : 4).append(']').append(names[i]);
		}
		return sb.toString();
	}

	static final String THANKS_1 = thanks("steve bailey", "karl vibert", "peter hanney", "neil pearce");

	static final String THANKS_2 = thanks("mark goodall", "oli cauberghe", "andrew walker", "jamie walker");

	static final String THANKS_3 = thanks("james warner", "wez ditch", "edward roller", "julian lorkin");

	/**
	 * The high score table.
	 *
	 * @param highlight
	 *            An entry to show in green (a new one), or <code>null</code>.
	 * @param pendingInitials
	 *            What to show as the highlighted entry's initials while they
	 *            are being typed, or <code>null</code> to show the real ones.
	 */
	static String highScores(HighScores hs, HighScores.Entry highlight, String pendingInitials) {
		List<HighScores.Entry> es = hs.entries();
		StringBuilder sb = new StringBuilder("[c4][k1]hi-scores[k][p][t3,");
		sb.append(es.size()).append("][hp25]");
		for (int i = 0; i < es.size(); i++) {
			HighScores.Entry e = es.get(i);
			boolean mine = e == highlight;
			String initials = mine && pendingInitials != null ? pendingInitials : e.initials;
			if (initials.isEmpty()) initials = " ";
			sb.append("[c0]").append(i + 1).append(".[e]");
			sb.append(mine ? "[c2]" : "[c5]").append(String.format("%07d", e.score)).append("[e]");
			sb.append(mine ? "[c2]" : "[c4]").append(initials).append("[e]");
		}
		return sb.toString();
	}

	static String enterInitials(HighScores hs, HighScores.Entry e, String soFar) {
		return "[c2]well done![p][c0]enter your name[n]" //
				+ "[c5]type it, or up and down then jump[p]" //
				+ highScores(hs, e, soFar);
	}

	/** comp1_text to comp9_text. */
	static String[] ending(int levelsPlayed, int gemsCollected) {
		return new String[] { //
				"[c2][k1]congratulations![k][p]" //
						+ "[c0]you have completed[n]" //
						+ "[c4]tearaway thomas", //

				"[c0]there are a total of 50[n]" //
						+ "stages in tearaway thomas[n]" //
						+ "[c5](crikey! thats what[n]" //
						+ "i call value!)[p]" //
						+ "[c0]you played [c4]" + levelsPlayed + "[c0] of them.", //

				"[c0]you collected [c4]" + gemsCollected + "[c0] out[n]" //
						+ "of a possible 3001 gems[p]" //
						+ "[c5]tearaway was written[n]" //
						+ "in our spare time over[n]" //
						+ "9 months.[n]" //
						+ "it's our first[n]" //
						+ "commercial game.", //

				"[c0]most of it was developed[n]" //
						+ "on a base a500![p]" //
						+ "[c5]when the source code was[n]" //
						+ "taking 40 seconds to save[n]" //
						+ "we figured it was time to[n]" //
						+ "get a hard-drive!", //

				"[c0]the graphics were drawn[n]" //
						+ "in deluxe paint 3 then[n]" //
						+ "converted to our own bob[n]" //
						+ "format.", //

				"[c0]all the data for tearaway[n]" //
						+ "was packed with our own[n]" //
						+ "compressor but you[n]" //
						+ "probably haven't noticed[n]" //
						+ "because it unpacks[n]" //
						+ "so fast!", //

				"[c0]the music was composed[n]" //
						+ "on our own sound-tracker.[n]" //
						+ "our digital instruments use[n]" //
						+ "less than 100 bytes[n]" //
						+ "each.", //

				"[c0]the code (18,000 lines of it)[n]" //
						+ "was developed in[n]" //
						+ "[c2]dde[c0] - our own custom[n]" //
						+ "development system.", //

				"[c0]see you in[n]" //
						+ "[c4]tearaway 2[p]" //
						+ "[c0]or[p]" //
						+ "[c4]super tearaway[n]" //
						+ "[c0]on the snes", //
		};
	}
}
