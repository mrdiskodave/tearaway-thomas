package com.nney.json;

public class IndentedJsonFormatter extends SimpleJsonFormatter {
	public String stringNewLine = "\n";
	public String stringIndent = "\t";

	public IndentedJsonFormatter(SafeWriter sw) {
		super(sw);
	}

	@Override
	public void spaciousBrackets() {
	}

	@Override
	public void spaciousSeperators() {
		stringDictSep = ": ";
	}

	private boolean eolNext;

	private void eol() {
		eolNext = true;
	}

	@Override
	public void beginArray() {
		super.beginArray();
		eol();
	}

	@Override
	public void beginDict() {
		super.beginDict();
		eol();
	}

	@Override
	public void value(String s) {
		super.value(s);
		eol();
	}

	@Override
	protected void makeOutput(String s) {
		if (eolNext) {
			super.makeOutput(stringNewLine);
			for (int x = 0; x < depth(); x++) {
				super.makeOutput(stringIndent);
			}
			eolNext = false;
		}
		super.makeOutput(s);
	}
}
