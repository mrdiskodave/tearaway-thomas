package com.nney;

import java.util.ArrayList;
import java.util.List;

public class FrameFinder {
	//
	// ---------------------------------------------
	// state
	//
	//

	String file;
	int pos;

	//
	// ---------------------------------------------
	// parser
	//
	//

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
			case 'w':
			case '0':
				// select a file
				// TODO: substitute 'w' for the world id
				setFile(item);
				break;
			case 'n':
				// a number of frames
				int counter = parseIntOrDefault(arg, 1);
				getFrames(frames, counter);
				break;
			case 'c':
				// a cycle of frames
				// forwards
				getCycle(frames, arg);
				break;
			case 'm':
				// move within the frames
				move(arg);
				break;
			default:
				assert false : command;
			}
		}
		return (Frame[]) frames.toArray(new Frame[frames.size()]);
	}

	//
	// ---------------------------------------------
	// commands
	//
	//
	
	private void move(String arg) {
		pos += parseIntOrDefault(arg, 0);
	}

	private void setFile(String item) {
		file = item;
		pos = 0;
	}

	private void getFrames(List<Frame> frames, int counter) {
		for (int x = 0; x < counter; x++) {
			frames.add(new Frame(file, pos));
			pos++;
		}
	}
	

	private void getCycle(List<Frame> frames, String arg) {
		int counter = parseIntOrDefault(arg, 1);
		assert counter > 2;
		getFrames(frames, counter);
		// back (need not repeat start or end of cycle)
		int p = frames.size() - 2;
		for (int x = 0; x < counter - 2; x++) {
			frames.add(frames.get(p - x));
		}
	}
}
