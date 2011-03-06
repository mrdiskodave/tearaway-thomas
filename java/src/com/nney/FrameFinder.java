package com.nney;

import java.util.ArrayList;
import java.util.List;

public class FrameFinder {
	String cFile;
	int cNumber;

	private static int parseIntOrDefault(String s, int d) {
		if (s.length() == 0)
			return d;
		return Integer.parseInt(s);
	}

	Frame[] parse(String descr) {
		List<Frame> frames = new ArrayList<Frame>();
		for (String item : descr.split(",")) {
			char command = item.charAt(0);
			String arg = item.substring(1);
			switch (command) {
			case 'n':
				for (int x = 0; x < parseIntOrDefault(arg, 1); x++) {
					frames.add(new Frame(cFile, cNumber));
					cNumber++;
				}
				break;
			case 'w':
			case '0':
				// TODO: substitue 'w' for the world id
				cFile = item;
				cNumber = 0;
				break;
			case 'j':
				cNumber = parseIntOrDefault(arg, 0);
				break;
			default:
				assert false : command;
			}
		}
		return (Frame[]) frames.toArray(new Frame[frames.size()]);
	}
}
