package com.nney.tt.osd;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class OsdParser {
	private static final Pattern OSD_CONTENT_PATTERN = Pattern.compile("\\[([a-z]+)(.*?)\\]");
	private static final Pattern OSD_TABLE_ARGS = Pattern.compile("(\\d+),(\\d+)");
	private final TextDest td;

	public OsdParser(TextDest td) {
		this.td = td;
	}

	public void parse(String text) {
		int pos = 0;
		Matcher m = OSD_CONTENT_PATTERN.matcher(text.substring(pos));
		while (m.find()) {
			sendAddText(text.substring(pos, m.start()));
			String cmd = m.group(1);
			String param = m.group(2);
			if (cmd.equals("n")) {
				td.addCr();
			}
			else if (cmd.equals("p")) {
				td.addParagraph();
			}
			else if (cmd.equals("a")) {
				td.addAdv(optN(param));
			}
			else if (cmd.equals("c")) {
				td.setCol(optN(param));
			}
			else if (cmd.equals("k")) {
				td.setKern(optN(param));
			}
			else if (cmd.equals("t")) {
				Matcher m2 = OSD_TABLE_ARGS.matcher(param);
				if (!m2.matches()) {
					throw new RuntimeException("Bad table param: " + param);
				}
				String[] z = param.split(",");
				int w = i(z[0]);
				int h = i(z[1]);
				td.addTable(w, h);
			}
			else if (cmd.equals("e")) {
				td.endCell();
			}
			else if (cmd.equals("hp")) {
				td.setHorizontalPadding(i(param));
			}
			else {
				assert false : "Unknown command:" + cmd;
			}
			pos = m.end();
		}
		sendAddText(text.substring(pos));
	}

	public void sendAddText(String s) {
		if (s.length() != 0) td.addText(s);
	}

	private static int i(String s) {
		return Integer.parseInt(s);
	}

	private int optN(String param) {
		return param.length() != 0 ? Integer.parseInt(param) : 0;
	}
}
