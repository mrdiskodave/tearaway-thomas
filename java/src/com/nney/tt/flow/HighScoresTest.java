package com.nney.tt.flow;

import java.io.File;
import java.nio.file.Files;

import junit.framework.TestCase;

public class HighScoresTest extends TestCase {
	public void testStartsWithTheOriginalTable() {
		HighScores hs = new HighScores(null);
		assertEquals(10, hs.entries().size());
		assertEquals(500000, hs.entries().get(0).score);
		assertEquals("deh", hs.entries().get(0).initials);
		assertEquals("wez", hs.entries().get(9).initials);
	}

	public void testQualifying() {
		HighScores hs = new HighScores(null);
		assertFalse(hs.qualifies(50000)); // has to beat the bottom one
		assertTrue(hs.qualifies(50001));
		assertNull(hs.add(10));

		HighScores.Entry e = hs.add(420000);
		assertNotNull(e);
		assertEquals(2, hs.rankOf(e));
		assertEquals(10, hs.entries().size());
		assertEquals("jcw", hs.entries().get(9).initials); // wez dropped off
	}

	public void testSavesAndLoads() throws Exception {
		File dir = Files.createTempDirectory("tt").toFile();
		File f = new File(new File(dir, "sub"), "hiscores.txt");
		HighScores hs = new HighScores(f);
		hs.add(999999).initials = "abc";
		hs.save();

		HighScores again = new HighScores(f);
		assertEquals(999999, again.entries().get(0).score);
		assertEquals("abc", again.entries().get(0).initials);
	}

	public void testCorruptFileFallsBackToOriginal() throws Exception {
		File f = File.createTempFile("ttscores", ".txt");
		Files.write(f.toPath(), "not a number at all\n".getBytes());
		HighScores hs = new HighScores(f);
		assertEquals(500000, hs.entries().get(0).score);
	}

	public void testCleanKeepsDrawableCharacters() {
		assertEquals("dav", HighScores.clean("DAVE"));
		assertEquals("a1", HighScores.clean("a:1"));
	}
}
