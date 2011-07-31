package com.nney.tt.osd;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class OsdParser {
	private static final Pattern OSD_CONTENT_PATTERN = Pattern.compile("\\[([a-z])(\\d*)\\]");
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
			boolean gotParam = param.length() != 0; 
			int nparam = gotParam ? Integer.parseInt(param) : -1;
			if (cmd == 'n') {
				td.addCr();
			}
			else if (cmd == 'p') {
				td.addParagraph();
			}
			else if (cmd=='a') {
				td.addAdv(gotParam ? nparam : 0);
			}
			else if (cmd == 'c') {
				td.setCol(gotParam ? nparam : 0);
			}
			else if (cmd == 'k') {
				td.setKern(gotParam ? nparam : 0);
			}
			pos = m.end();
		}
		td.addText(text.substring(pos));
	}
}
