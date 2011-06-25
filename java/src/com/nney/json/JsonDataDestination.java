package com.nney.json;

import java.util.Stack;

public class JsonDataDestination implements DataDestination {
	private StringBuilder sb = new StringBuilder();
	private enum State {
		LIST_START,
		LIST_NEXT,
		DICT_KEY,
		DICT_NEXT_KEY,
		DICT_VALUE,
	}
	
	private Stack<State> stack = new Stack<State>();
	private Stack<Character> term = new Stack<Character>();
	
	private State state = State.LIST_START;
	
	@Override
	public void beginArray() {
		begin('[', ']', State.LIST_START);
	}

	@Override
	public void beginDict() {
		begin('{', '}', State.DICT_KEY);
	}

	private void begin(char open, char shut, State newState) {
		cantBeWaitingForDictKey();
		stateChangeForValues();
		put(open+" ");
		stack.push(state);
		term.push(shut);
		state = newState;
	}

	@Override
	public void end() {
		if (state==State.DICT_VALUE) {
			throw new IllegalStateException("Dictionary must have an even number of values (key/value key/value etc)");
		}
		if (stack.empty()) {
			throw new IllegalStateException("end() without begin()");
		}
		char t = term.pop();
		state = stack.pop();
		put(" "+t);
	}

	@Override
	public void write(double value) {
		throw new RuntimeException("not implemented");
	}
	
	@Override
	public void write(int value) {
		cantBeWaitingForDictKey();
		w(String.format("%s", value));
	}

	private void cantBeWaitingForDictKey() {
		if (state == State.DICT_KEY || state==State.DICT_NEXT_KEY) {
			throw new IllegalArgumentException("Dictionary keys can only be Strings");
		}
	}

	private void w(String s) {
		stateChangeForValues();
		
		// expecting value string?
		put(s);
	}

	private void stateChangeForValues() {
		if (state == State.LIST_START) {
			state = State.LIST_NEXT;
		}
		else if (state == State.LIST_NEXT) {
			put(", ");
		}
		else if (state == State.DICT_KEY) {
			state = State.DICT_VALUE;
		}
		else if (state == State.DICT_VALUE) {
			put(": ");
			state = State.DICT_NEXT_KEY;
		}
		else if (state == State.DICT_NEXT_KEY) {
			put(", ");
			state = State.DICT_VALUE;
		}
	}

	private void put(String s) {
		sb.append(s);
		System.out.println(">"+s+"<");
	}

	@Override
	public void write(long value) {
		cantBeWaitingForDictKey();
		w(String.format("%s", value));
	}

	@Override
	public void write(boolean value) {
		cantBeWaitingForDictKey();
		w(value ? "true" : "false");
	}

	@Override
	public void write(String value) {
		StringBuffer b = new StringBuffer();
		b.append('"');
		for (int x=0; x<value.length(); x++) {
			char c = value.charAt(x);
			switch (c) {
			case '\b':
				b.append("\\b");
				break;
			case '\f':
				b.append("\\f");
				break;
			case '\n':
				b.append("\\n");
				break;
			case '\r':
				b.append("\\r");
				break;
			case '\t':
				b.append("\\t");
				break;
			default:
				if (c>31 && c<128) {
					b.append(c);
				}
				else {
					b.append(String.format("\\u%04x", (int) c));
				}
			}
		}
		b.append('"');
		w(b.toString());
	}
	
	@Override
	public String toString() {
		return sb.toString();
	}
}
