package com.nney.json;

import java.util.Stack;

import com.nney.datanode.DataDestination;

public class JsonDataDestination implements DataDestination {
	private SimpleJsonFormatter target;

	private enum State {
		LIST_ITEM, DICT_KEY, DICT_VALUE,
	}

	public JsonDataDestination(SimpleJsonFormatter target) {
		this.target = target;
	}

	private Stack<State> stack = new Stack<>();

	private State state = State.LIST_ITEM;

	private void stateChange() {
		if (state == State.DICT_KEY) {
			state = State.DICT_VALUE;
		}
		else if (state == State.DICT_VALUE) {
			state = State.DICT_KEY;
		}
	}

	private boolean waitingForKey() {
		return state == State.DICT_KEY;
	}

	private void outputValue(String s) {
		if (waitingForKey()) {
			throw new IllegalArgumentException("Dictionary keys can only be Strings");
		}
		stateChange();
		target.value(s);

	}

	private void outputValueString(String s) {
		boolean w = waitingForKey();
		stateChange();
		if (w) {
			target.key(s);
		}
		else {
			target.value(s);
		}
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
		begin(State.LIST_ITEM);
	}

	@Override
	public void beginObject() {
		stateChange();
		target.beginDict();
		begin(State.DICT_KEY);
	}

	@Override
	public void write(double value) {
		outputValue(String.format("%s", value));
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
		StringBuilder b = new StringBuilder();
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
		outputValueString(b.toString());
	}
}
