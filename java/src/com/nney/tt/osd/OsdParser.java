package com.nney.tt.osd;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class OsdParser {
	private static final Pattern OSD_CONTENT_PATTERN = Pattern.compile("\\[([a-z])(.*?)\\]");
	private static final Pattern OSD_TABLE_ARGS = Pattern.compile("(\\d+),(\\d+)");
	private final TextDest td;

	public OsdParser(TextDest td) {
		this.td = td;
	}

	public void parse(String text) {
		int pos = 0;
		Matcher m = OSD_CONTENT_PATTERN.matcher(text.substring(pos));
		while (m.find()) {
			td.addText(text.substring(pos, m.start()));
			int cmd = m.group(1).charAt(0);
			String param = m.group(2);
			if (cmd == 'n') {
				td.addCr();
			}
			else if (cmd == 'p') {
				td.addParagraph();
			}
			else if (cmd=='a') {
				td.addAdv(optN(param));
			}
			else if (cmd == 'c') {
				td.setCol(optN(param));
			}
			else if (cmd == 'k') {
				td.setKern(optN(param));
			}
			else if (cmd=='t') {
				System.out.println(param);
				Matcher m2 = OSD_TABLE_ARGS.matcher(param);
				if (!m2.matches()) {
					throw new RuntimeException("Bad table param: "+param);
				}
				int w = Integer.parseInt(m2.group(1));
				int h = Integer.parseInt(m2.group(2));
				td.addTable(w, h);
			}
			else if (cmd=='e') {
				td.endCell();
			}
			pos = m.end();
		}
		td.addText(text.substring(pos));
	}

	private int optN(String param) {
		return param.length() != 0 ? Integer.parseInt(param) : 0;
	}
}
