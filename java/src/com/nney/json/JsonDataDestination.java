package com.nney.json;

import java.util.Stack;

public class JsonDataDestination implements DataDestination {
	private StringBuilder sb = new StringBuilder();

	private enum State {
		LIST_START, // to LIST_NEXT
		LIST_NEXT, // to LIST_NEXT

		DICT_START, // to DICT_VALUE
		DICT_NEXT, // to DICT_VALUE
		DICT_VALUE, // to DICT_NEXT
	}

	private Stack<State> stack = new Stack<State>();
	private Stack<String> term = new Stack<String>();

	private State state = State.LIST_START;

	private String stringListSep = ", ";
	private String stringDictSep = ": ";
	private String stringArrayBegin = "[ ";
	private String stringArrayEnd = " ]";
	private String stringDictBegin = "{ ";
	private String stringDictEnd = " }";

	private void put(String s) {
		sb.append(s);
		System.out.println(">" + s + "<");
	}

	private void stateChange(boolean isName) {
		if (!isName) {
			boolean dictionaryKey = state == State.DICT_START || state == State.DICT_NEXT;
			if (dictionaryKey) {
				throw new IllegalArgumentException("Dictionary keys can only be Strings");
			}
		}
		
		if (state == State.LIST_START) {
			state = State.LIST_NEXT;
		}
		else if (state == State.LIST_NEXT) {
			put(stringListSep);
		}
		else if (state == State.DICT_START) {
			state = State.DICT_VALUE;
		}
		else if (state == State.DICT_VALUE) {
			put(stringDictSep);
			state = State.DICT_NEXT;
		}
		else if (state == State.DICT_NEXT) {
			put(stringListSep);
			state = State.DICT_VALUE;
		}
	}

	private void outputValue(String s, boolean isName) {
		stateChange(isName);
		put(s);
	}

	private void begin(String open, String shut, State newState) {
		stateChange(false);
		put(open);
		stack.push(state);
		term.push(shut);
		state = newState;
	}

	@Override
	public void end() {
		if (state == State.DICT_VALUE) {
			throw new IllegalStateException("Dictionary must have an even number of values (key/value key/value etc)");
		}
		if (stack.empty()) {
			throw new IllegalStateException("end() without begin()");
		}
		put(term.pop());
		state = stack.pop();
	}

	@Override
	public void beginArray() {
		begin(stringArrayBegin, stringArrayEnd, State.LIST_START);
	}

	@Override
	public void beginDict() {
		begin(stringDictBegin, stringDictEnd, State.DICT_START);
	}

	@Override
	public void write(double value) {
		throw new RuntimeException("not implemented");
	}

	@Override
	public void write(int value) {
		outputValue(String.format("%s", value), false);
	}

	@Override
	public void write(long value) {
		outputValue(String.format("%s", value), false);
	}

	@Override
	public void write(boolean value) {
		outputValue(value ? "true" : "false", false);
	}
	
	@Override
	public void writeNull() {
		outputValue("null", false);
	}

	@Override
	public void write(String value) {
		StringBuffer b = new StringBuffer();
		b.append('"');
		for (int x = 0; x < value.length(); x++) {
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
				if (c > 31 && c < 128) {
					b.append(c);
				}
				else {
					b.append(String.format("\\u%04x", (int) c));
				}
			}
		}
		b.append('"');
		outputValue(b.toString(), true);
	}

	@Override
	public String toString() {
		return sb.toString();
	}
}
