package com.nney.tt.osd;

public class MockTextDest implements TextDest {

	private StringBuffer answer = new StringBuffer();

	private void am(String string) {
		if (answer.length()!=0) {
			answer.append(',');
		}
		answer.append(string);
	}

	@Override
	public String toString() {
		return answer.toString();
	}

	@Override
	public void addText(String text) {
		if (text.length()!=0) am("text:"+text);
	}

	@Override
	public void addCr() {
		am("cr");
	}

	@Override
	public void addParagraph() {
		am("para");
	}

	@Override
	public void addAdv(int size) {
		am("adv:"+size);

	}

	@Override
	public void setCol(int v) {
		am("col:"+v);

	}

	@Override
	public void setKern(int v) {
		am("kern:"+v);
	}

	@Override
	public void addTable(int w, int h) {
		am("table:"+w+","+h);
		
	}

	@Override
	public void endCell() {
		am("endCell");
	}

	@Override
	public void setHorizontalPadding(int hp) {
		am("hp:"+hp);
	}
}
