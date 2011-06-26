package com.nney.json;

import java.util.Stack;

public class JsonDataDestination implements DataDestination {
	private SimpleJsonFormatter target;

	private enum State {
		LIST_START, // to LIST_NEXT
		LIST_NEXT, // to LIST_NEXT

		DICT_START, // to DICT_VALUE
		DICT_NEXT, // to DICT_VALUE
		DICT_VALUE, // to DICT_NEXT
	}

	JsonDataDestination(SimpleJsonFormatter target) {
		this.target = target;
	}

	private Stack<State> stack = new Stack<State>();

	private State state = State.LIST_START;

	private String key;

	private void stateChange() {
		if (state == State.LIST_START) {
			state = State.LIST_NEXT;
		}
		else if (state == State.LIST_NEXT) {
			target.listSep();
		}
		else if (state == State.DICT_START) {
			state = State.DICT_VALUE;
		}
		else if (state == State.DICT_VALUE) {
			target.dictSep();
			state = State.DICT_NEXT;
		}
		else if (state == State.DICT_NEXT) {
			target.listSep();
			state = State.DICT_VALUE;
		}
	}

	private boolean waitingForKey() {
		return state == State.DICT_START || state == State.DICT_NEXT;
	}

	private void outputValue(String s) {
		if (waitingForKey()) {
			throw new IllegalArgumentException("Dictionary keys can only be Strings");
		}

		stateChange();
		target.value(s);
	}
	
	private void outputValueString(String s) {
		stateChange();
		target.value(s);
	}
	
	@Override
	public void end() {
		if (state == State.DICT_VALUE) {
			throw new IllegalStateException("Dictionary must have an even number of values (key/value key/value etc)");
		}
		if (stack.empty()) {
			throw new IllegalStateException("end() without begin()");
		}
		target.end();
		state = stack.pop();
	}

	private void begin(State newState) {
		stack.push(state);
		state = newState;
	}

	@Override
	public void beginArray() {
		stateChange();
		target.beginArray();
		begin(State.LIST_START);
	}

	@Override
	public void beginDict() {
		stateChange();
		target.beginDict();
		begin(State.DICT_START);
	}

	@Override
	public void write(double value) {
		throw new RuntimeException("not implemented");
	}

	@Override
	public void write(int value) {
		outputValue(String.format("%s", value));
	}

	@Override
	public void write(long value) {
		outputValue(String.format("%s", value));
	}

	@Override
	public void write(boolean value) {
		outputValue(value ? "true" : "false");
	}

	@Override
	public void writeNull() {
		outputValue("null");
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
//		if (waitingForKey()) {
//			key = b.toString();
//			stateChange();
//		}
		outputValueString(b.toString());
	}
}
