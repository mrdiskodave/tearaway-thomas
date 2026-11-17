package com.nney.datanode;

/**
 * This {@link DataDestination} is sloppy because different unique input
 * sequences might make the same output string. This means it is non-reversible
 * so you can make your data into a String but cannot get it back. On the upside
 * it is fast.
 */
public final class SimpleDataDestination implements DataDestination {
	StringBuilder sb = new StringBuilder();

	private void sep() {
		sb.append('\u0000');
	}

	@Override
	public void beginArray() {
		sb.append('[');
		sep();
	}

	@Override
	public void beginObject() {
		sb.append('{');
		sep();
	}

	@Override
	public void end() {
		sb.append('/');
		sep();
	}

	@Override
	public void write(double value) {
		sb.append(value);
		sep();
	}

	@Override
	public void write(int value) {
		sb.append(value);
		sep();
	}

	@Override
	public void write(long value) {
		sb.append(value);
		sep();
	}

	@Override
	public void write(boolean value) {
		sb.append(value);
		sep();
	}

	@Override
	public void write(String value) {
		sb.append(value);
		sep();
	}

	@Override
	public void writeNull() {
		sb.append('n');
		sep();
	}

	@Override
	public String toString() {
		return sb.toString();
	}
}
