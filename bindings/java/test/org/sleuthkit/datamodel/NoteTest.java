/*
 * Sleuth Kit Data Model
 *
 * Copyright 2026 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.datamodel;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.AfterClass;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * Tests the Note apis.
 *
 */
public class NoteTest {

	private static final Logger LOGGER = Logger.getLogger(NoteTest.class.getName());

	private static final String MODULE_NAME = "NoteTest";

	private final static String TEST_DB = "NoteApiTest.db";

	private static SleuthkitCase caseDB;
	private static String dbPath = null;
	private static Image image = null;
	private static FileSystem fs = null;

	private static NoteType commentType;
	private static NoteType summaryType;

	private static final Note.Author ANALYST = new Note.Author(Note.AuthorKind.USER, "user-1", "Alice Analyst");
	private static final Note.Author OTHER_ANALYST = new Note.Author(Note.AuthorKind.USER, "user-2", "Bob Analyst");
	private static final Note.Author MODEL = new Note.Author(Note.AuthorKind.AI, "model-1", "Some Model", "prompt-v1");

	public NoteTest() {

	}

	@BeforeClass
	public static void setUpClass() {
		String tempDirPath = System.getProperty("java.io.tmpdir");
		try {
			dbPath = Paths.get(tempDirPath, TEST_DB).toString();

			// Delete the DB file, in case
			java.io.File dbFile = new java.io.File(dbPath);
			dbFile.delete();
			if (dbFile.getParentFile() != null) {
				dbFile.getParentFile().mkdirs();
			}

			caseDB = SleuthkitCase.newCase(dbPath);

			SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();
			image = caseDB.addImage(TskData.TSK_IMG_TYPE_ENUM.TSK_IMG_TYPE_DETECT, 512, 1024, "", Collections.emptyList(), "America/NewYork", null, null, null, "first", trans);
			fs = caseDB.addFileSystem(image.getId(), 0, TskData.TSK_FS_TYPE_ENUM.TSK_FS_TYPE_RAW, 0, 0, 0, 0, 0, "", trans);
			trans.commit();

			commentType = caseDB.getNoteManager().getNoteType(NoteType.BuiltIn.COMMENT.getTypeName()).orElseThrow(()
					-> new TskCoreException("COMMENT note type was not seeded"));
			summaryType = caseDB.getNoteManager().getNoteType(NoteType.BuiltIn.AI_SUMMARY.getTypeName()).orElseThrow(()
					-> new TskCoreException("AI_SUMMARY note type was not seeded"));

			System.out.println("Note Test DB created at: " + dbPath);
		} catch (TskCoreException ex) {
			LOGGER.log(Level.SEVERE, "Failed to create new case", ex);
		}
	}

	@AfterClass
	public static void tearDownClass() {

	}

	/**
	 * The built-in types are seeded on every open, and a consumer can add its
	 * own without a schema change. Adding one twice must give back the same
	 * row, since two clients of a PostgreSQL case can do it at once.
	 */
	@Test
	public void noteTypeTests() throws TskCoreException {
		NoteManager noteManager = caseDB.getNoteManager();

		for (NoteType.BuiltIn builtIn : NoteType.BuiltIn.values()) {
			Optional<NoteType> seeded = noteManager.getNoteType(builtIn.getTypeName());
			assertTrue("Built-in note type " + builtIn.getTypeName() + " was not seeded", seeded.isPresent());
			assertEquals(builtIn.getDisplayName(), seeded.get().getDisplayName().orElse(null));
		}

		NoteType custom = noteManager.getOrAddNoteType("NOTE_TEST_CUSTOM", "Custom");
		NoteType again = noteManager.getOrAddNoteType("NOTE_TEST_CUSTOM", "A different display name");
		assertEquals(custom.getNoteTypeId(), again.getNoteTypeId());
		assertEquals("Custom", again.getDisplayName().orElse(null));

		assertTrue(noteManager.getNoteTypes().size() >= NoteType.BuiltIn.values().length + 1);
	}

	/**
	 * A note on a file records what the caller gave it, and the manager fills
	 * in the columns the caller does not supply: the data source, and the self
	 * references that make it its own thread root and its own first version.
	 */
	@Test
	public void addNoteTests() throws TskCoreException {
		NoteManager noteManager = caseDB.getNoteManager();
		AbstractFile file = addFile("addNote.txt");

		Note note = noteManager.addNote(new NoteRequest(file.getId(), commentType,
				"Looks like a dropper", "{\"priority\":\"HIGH\"}", ANALYST, null, null, null));

		assertEquals(file.getId(), note.getObjectId());
		assertEquals("Looks like a dropper", note.getBody());
		assertEquals("{\"priority\":\"HIGH\"}", note.getDetails().orElse(null));
		assertEquals(ANALYST.getId(), note.getAuthor().getId());
		assertEquals(Note.AuthorKind.USER, note.getAuthor().getKind());
		assertFalse(note.getAuthor().getConfigId().isPresent());
		assertTrue(note.isCurrent());
		assertFalse(note.isDeleted());

		// Derived by the manager, not passed in.
		assertEquals(Long.valueOf(image.getId()), note.getDataSourceObjectId().orElse(null));
		assertEquals(note.getNoteId(), note.getRootNoteId());
		assertEquals(note.getNoteId(), note.getOriginalNoteId());

		// What was written is what comes back.
		List<Note> read = noteManager.getNotes(file.getId());
		assertEquals(1, read.size());
		assertNoteEquals(note, read.get(0));

		// An AI note carries the prompt version, so a bad answer can be told from an old one.
		Note aiNote = noteManager.addNote(new NoteRequest(file.getId(), summaryType, "Nothing notable", MODEL));
		assertEquals(Note.AuthorKind.AI, aiNote.getAuthor().getKind());
		assertEquals("prompt-v1", aiNote.getAuthor().getConfigId().orElse(null));

		assertEquals(2, noteManager.getNotes(file.getId()).size());
		assertEquals(1, noteManager.getNotes(file.getId(), commentType).size());
	}

	/**
	 * A reply joins its parent's thread and reads back with it in one query. A
	 * reply on a different object is rejected, so a thread cannot span objects.
	 */
	@Test
	public void threadTests() throws TskCoreException {
		NoteManager noteManager = caseDB.getNoteManager();
		AbstractFile file = addFile("thread.txt");
		AbstractFile otherFile = addFile("threadOther.txt");

		Note root = noteManager.addNote(new NoteRequest(file.getId(), commentType, "Is this expected?", ANALYST));
		Note reply = noteManager.addNote(new NoteRequest(file.getId(), commentType, "No, it is not",
				null, OTHER_ANALYST, root.getNoteId(), null, null));
		Note replyToReply = noteManager.addNote(new NoteRequest(file.getId(), commentType, "Agreed",
				null, ANALYST, reply.getNoteId(), null, null));

		assertEquals(root.getNoteId(), reply.getRootNoteId());
		assertEquals(root.getNoteId(), replyToReply.getRootNoteId());
		assertEquals(Long.valueOf(reply.getNoteId()), replyToReply.getParentNoteId().orElse(null));

		// A reply is its own first version, even though it is not its own root.
		assertEquals(reply.getNoteId(), reply.getOriginalNoteId());

		List<Note> thread = noteManager.getThread(root.getNoteId());
		assertEquals(3, thread.size());
		assertEquals(root.getNoteId(), thread.get(0).getNoteId());

		try {
			noteManager.addNote(new NoteRequest(otherFile.getId(), commentType, "Wrong object",
					null, ANALYST, root.getNoteId(), null, null));
			fail("Expected a reply on a different object to be rejected");
		} catch (TskCoreException ex) {
			assertTrue(ex.getMessage().contains("cannot span objects"));
		}
	}

	/**
	 * Revising appends. The previous text keeps its row and stops being
	 * current, the new row joins the same lineage, and anything holding the
	 * original id still resolves to the live text.
	 */
	@Test
	public void reviseNoteTests() throws TskCoreException {
		NoteManager noteManager = caseDB.getNoteManager();
		AbstractFile file = addFile("revise.txt");

		Note first = noteManager.addNote(new NoteRequest(file.getId(), commentType, "First draft", ANALYST));
		Note second = noteManager.reviseNote(first.getNoteId(), "Second draft", "{\"v\":2}", ANALYST);

		assertNotEquals(first.getNoteId(), second.getNoteId());
		assertEquals(first.getOriginalNoteId(), second.getOriginalNoteId());
		assertEquals(first.getRootNoteId(), second.getRootNoteId());
		assertTrue(second.isCurrent());

		Optional<Note> current = noteManager.getCurrentRevision(first.getOriginalNoteId());
		assertTrue(current.isPresent());
		assertEquals(second.getNoteId(), current.get().getNoteId());
		assertEquals("Second draft", current.get().getBody());

		// The broad read hands back both drafts; the narrow one hands back the live text.
		List<Note> revisions = noteManager.getRevisions(first.getOriginalNoteId());
		assertEquals(2, revisions.size());
		assertEquals(first.getNoteId(), revisions.get(0).getNoteId());
		assertFalse(revisions.get(0).isCurrent());

		List<Note> currentNotes = noteManager.getCurrentNotes(file.getId(), commentType);
		assertEquals(1, currentNotes.size());
		assertEquals("Second draft", currentNotes.get(0).getBody());

		// A model revising its own summary is the same author with a newer prompt.
		Note summary = noteManager.addNote(new NoteRequest(file.getId(), summaryType, "Nothing yet", MODEL));
		Note regenerated = noteManager.reviseNote(summary.getNoteId(), "One notable item", null,
				new Note.Author(Note.AuthorKind.AI, MODEL.getId(), MODEL.getDisplayName(), "prompt-v2"));
		assertEquals("prompt-v2", regenerated.getAuthor().getConfigId().orElse(null));

		// A superseded revision is not the one to revise.
		try {
			noteManager.reviseNote(first.getNoteId(), "Too late", null, ANALYST);
			fail("Expected revising a superseded revision to be rejected");
		} catch (TskCoreException ex) {
			assertTrue(ex.getMessage().contains("superseded"));
		}
	}

	/**
	 * You revise your own note and reply to someone else's. There is no path
	 * that rewrites another person's words under their name, so every revision
	 * in a lineage has one author.
	 */
	@Test
	public void reviseRejectsADifferentAuthorTest() throws TskCoreException {
		NoteManager noteManager = caseDB.getNoteManager();
		AbstractFile file = addFile("author.txt");

		Note note = noteManager.addNote(new NoteRequest(file.getId(), commentType, "Mine", ANALYST));
		try {
			noteManager.reviseNote(note.getNoteId(), "Not yours to edit", null, OTHER_ANALYST);
			fail("Expected revising another author's note to be rejected");
		} catch (TskCoreException ex) {
			assertTrue(ex.getMessage().contains("different author"));
		}

		// Nothing was written.
		assertEquals(1, noteManager.getRevisions(note.getOriginalNoteId()).size());
		assertEquals("Mine", noteManager.getCurrentRevision(note.getOriginalNoteId()).get().getBody());
	}

	/**
	 * The revision flip is a check-then-act with no lock behind it on
	 * PostgreSQL, so it is settled by a constraint instead. Two current
	 * revisions of one note have to be impossible rather than merely unlikely.
	 */
	@Test
	public void uniqueIndexRejectsASecondCurrentRevisionTest() throws TskCoreException {
		NoteManager noteManager = caseDB.getNoteManager();
		AbstractFile file = addFile("concurrent.txt");

		Note first = noteManager.addNote(new NoteRequest(file.getId(), commentType, "First", ANALYST));
		noteManager.reviseNote(first.getNoteId(), "Second", null, ANALYST);

		// Stand in for a second writer that flipped is_current without noticing the
		// first one had already done it.
		try (SleuthkitCase.CaseDbConnection connection = caseDB.getConnection();
				Statement s = connection.createStatement()) {

			s.executeUpdate("UPDATE tsk_notes SET is_current = 1 WHERE note_id = " + first.getNoteId());
			fail("Expected the unique index to reject a second current revision");
		} catch (SQLException ex) {
			// Expected.
		}

		assertEquals(1, noteManager.getCurrentNotes(file.getId(), commentType).size());
	}

	/**
	 * A note written through addNotes() must be indistinguishable from one
	 * written through addNote() on the columns the manager derives. That is the
	 * whole reason the self references are back-filled rather than
	 * pre-allocated.
	 */
	@Test
	public void batchAndSingleParityTest() throws TskCoreException {
		NoteManager noteManager = caseDB.getNoteManager();
		AbstractFile file = addFile("parity.txt");

		Note single = noteManager.addNote(new NoteRequest(file.getId(), commentType, "Written one at a time", ANALYST));

		SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();
		List<Note> batch;
		try {
			batch = noteManager.addNotes(Arrays.asList(
					new NoteRequest(file.getId(), commentType, "Written in a batch", ANALYST),
					new NoteRequest(file.getId(), commentType, "Also in the batch", ANALYST)), trans);
			trans.commit();
			trans = null;
		} finally {
			if (trans != null) {
				trans.rollback();
			}
		}

		assertEquals(2, batch.size());
		assertEquals("Written in a batch", batch.get(0).getBody());
		assertEquals("Also in the batch", batch.get(1).getBody());

		for (Note note : batch) {
			assertEquals("Batch root note should be its own thread root", note.getNoteId(), note.getRootNoteId());
			assertEquals("Batch root note should be its own first version", note.getNoteId(), note.getOriginalNoteId());
			assertEquals(single.getDataSourceObjectId(), note.getDataSourceObjectId());
		}

		// The returned objects have to match what was persisted, since callers use them
		// without reading back.
		for (Note note : batch) {
			assertNoteEquals(note, noteManager.getNoteById(note.getNoteId()).get());
		}

		// A reply written in a batch inherits its parent's thread the same way a reply
		// written on its own does.
		trans = caseDB.beginTransaction();
		List<Note> replies;
		try {
			replies = noteManager.addNotes(Collections.singletonList(
					new NoteRequest(file.getId(), commentType, "Batched reply", null, ANALYST, single.getNoteId(), null, null)), trans);
			trans.commit();
			trans = null;
		} finally {
			if (trans != null) {
				trans.rollback();
			}
		}
		assertEquals(single.getNoteId(), replies.get(0).getRootNoteId());
		assertEquals(replies.get(0).getNoteId(), replies.get(0).getOriginalNoteId());
	}

	/**
	 * The multi-row INSERT that PostgreSQL takes is the same SQL on either
	 * engine, so run it here and check that it writes the same rows, in the
	 * same order, as inserting one at a time. Without this the batched path
	 * would have no coverage at all in a SQLite-only test run.
	 */
	@Test
	public void batchedInsertPathTest() throws TskCoreException {
		NoteManager noteManager = caseDB.getNoteManager();
		AbstractFile file = addFile("batchedPath.txt");

		List<NoteRequest> requests = new ArrayList<>();
		for (int i = 0; i < 5; i++) {
			requests.add(new NoteRequest(file.getId(), commentType, "Note " + i,
					"{\"i\":" + i + "}", ANALYST, null, null, 1700000000000L + i));
		}

		SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();
		List<Note> batched;
		try {
			batched = noteManager.addNotes(requests, trans, true);
			trans.commit();
			trans = null;
		} finally {
			if (trans != null) {
				trans.rollback();
			}
		}

		assertEquals(5, batched.size());
		for (int i = 0; i < 5; i++) {
			Note note = batched.get(i);
			assertEquals("Batched notes must come back in request order", "Note " + i, note.getBody());
			assertEquals("{\"i\":" + i + "}", note.getDetails().orElse(null));
			assertEquals(1700000000000L + i, note.getCreatedTime());
			assertEquals(note.getNoteId(), note.getRootNoteId());
			assertEquals(note.getNoteId(), note.getOriginalNoteId());
			assertNoteEquals(note, noteManager.getNoteById(note.getNoteId()).get());
		}

		// A reply written through the batched path picks up its parent's thread just
		// as it does through the row at a time path.
		trans = caseDB.beginTransaction();
		try {
			List<Note> reply = noteManager.addNotes(Collections.singletonList(
					new NoteRequest(file.getId(), commentType, "Batched reply", null, ANALYST, batched.get(0).getNoteId(), null, null)),
					trans, true);
			trans.commit();
			trans = null;
			assertEquals(batched.get(0).getNoteId(), reply.get(0).getRootNoteId());
			assertEquals(reply.get(0).getNoteId(), reply.get(0).getOriginalNoteId());
		} finally {
			if (trans != null) {
				trans.rollback();
			}
		}
	}

	/**
	 * A hard delete takes the thread underneath the note, and every revision of
	 * it. A soft delete keeps the row so that a colleague's reply is not lost
	 * because someone retracted the note it hangs from.
	 */
	@Test
	public void deleteNoteTests() throws TskCoreException {
		NoteManager noteManager = caseDB.getNoteManager();
		AbstractFile file = addFile("delete.txt");

		Note root = noteManager.addNote(new NoteRequest(file.getId(), commentType, "Retract me", ANALYST));
		Note reply = noteManager.addNote(new NoteRequest(file.getId(), commentType, "Replying",
				null, OTHER_ANALYST, root.getNoteId(), null, null));

		noteManager.deleteNote(root.getNoteId(), NoteManager.DeleteMode.SOFT);
		List<Note> afterSoftDelete = noteManager.getThread(root.getNoteId());
		assertEquals(2, afterSoftDelete.size());
		assertTrue(afterSoftDelete.get(0).isDeleted());
		assertFalse("A soft delete must not touch the replies", afterSoftDelete.get(1).isDeleted());

		// A retraction stands. Revising the note would otherwise write a row that takes
		// the is_deleted default and quietly bring it back.
		try {
			noteManager.reviseNote(root.getNoteId(), "Actually, let me rephrase", null, ANALYST);
			fail("Expected revising a deleted note to be rejected");
		} catch (TskCoreException ex) {
			assertTrue(ex.getMessage().contains("has been deleted"));
		}
		assertTrue(noteManager.getCurrentRevision(root.getOriginalNoteId()).get().isDeleted());

		// Revise the reply first: the cascade has to take a reply that is several rows,
		// whose later revisions reference its first one.
		Note revisedReply = noteManager.reviseNote(reply.getNoteId(), "Replying, more carefully", null, OTHER_ANALYST);
		noteManager.addNote(new NoteRequest(file.getId(), commentType, "Reply to the reply",
				null, ANALYST, revisedReply.getNoteId(), null, null));

		noteManager.deleteNote(root.getNoteId(), NoteManager.DeleteMode.HARD);
		assertTrue(noteManager.getThread(root.getNoteId()).isEmpty());
		assertFalse(noteManager.getNoteById(reply.getNoteId()).isPresent());
		assertTrue(noteManager.getRevisions(reply.getOriginalNoteId()).isEmpty());

		// A revised note is more than one row, and a hard delete has to take all of
		// them: the later revisions reference the first.
		Note revised = noteManager.addNote(new NoteRequest(file.getId(), commentType, "First", ANALYST));
		noteManager.reviseNote(revised.getNoteId(), "Second", null, ANALYST);
		noteManager.deleteNote(revised.getNoteId(), NoteManager.DeleteMode.HARD);
		assertTrue(noteManager.getRevisions(revised.getOriginalNoteId()).isEmpty());

		assertTrue(noteManager.getNotes(file.getId()).isEmpty());
	}

	/**
	 * Both delete modes work on the whole revision lineage, so a consumer
	 * holding the stable original note id - which is what an analysis result's
	 * TSK_NOTE_ID attribute carries - retracts the note the reader can see, not
	 * just the draft that id happens to name.
	 */
	@Test
	public void deleteByOriginalNoteIdTest() throws TskCoreException {
		NoteManager noteManager = caseDB.getNoteManager();
		AbstractFile file = addFile("deleteByOriginal.txt");

		Note first = noteManager.addNote(new NoteRequest(file.getId(), commentType, "First", ANALYST));
		Note second = noteManager.reviseNote(first.getNoteId(), "Second", null, ANALYST);
		assertNotEquals("The stable id names the superseded draft after a revision",
				first.getOriginalNoteId(), second.getNoteId());

		noteManager.deleteNote(first.getOriginalNoteId(), NoteManager.DeleteMode.SOFT);

		for (Note revision : noteManager.getRevisions(first.getOriginalNoteId())) {
			assertTrue("Every revision in the lineage should be marked deleted", revision.isDeleted());
		}
		assertTrue(noteManager.getCurrentRevision(first.getOriginalNoteId()).get().isDeleted());

		noteManager.deleteNote(first.getOriginalNoteId(), NoteManager.DeleteMode.HARD);
		assertTrue(noteManager.getRevisions(first.getOriginalNoteId()).isEmpty());
	}

	/**
	 * A table of items needs a note count per row without loading any prose.
	 * The broad count includes every revision, matching the broad reads; the
	 * current count is the one a badge wants.
	 */
	@Test
	public void batchReadTests() throws TskCoreException {
		NoteManager noteManager = caseDB.getNoteManager();
		AbstractFile fileOne = addFile("batchReadOne.txt");
		AbstractFile fileTwo = addFile("batchReadTwo.txt");
		AbstractFile fileThree = addFile("batchReadThree.txt");

		Note revised = noteManager.addNote(new NoteRequest(fileOne.getId(), commentType, "First", ANALYST));
		noteManager.reviseNote(revised.getNoteId(), "Second", null, ANALYST);
		noteManager.addNote(new NoteRequest(fileTwo.getId(), commentType, "Only one", ANALYST));
		noteManager.addNote(new NoteRequest(fileTwo.getId(), summaryType, "A summary", MODEL));

		List<Long> objIds = Arrays.asList(fileOne.getId(), fileTwo.getId(), fileThree.getId());

		Map<Long, List<Note>> comments = noteManager.getNotes(objIds, commentType);
		assertEquals(2, comments.get(fileOne.getId()).size());
		assertEquals(1, comments.get(fileTwo.getId()).size());
		assertFalse("Objects with no note are absent from the map", comments.containsKey(fileThree.getId()));

		Map<Long, Integer> allCounts = noteManager.getNoteCounts(objIds, commentType);
		assertEquals(Integer.valueOf(2), allCounts.get(fileOne.getId()));
		assertEquals(Integer.valueOf(1), allCounts.get(fileTwo.getId()));

		Map<Long, Integer> currentCounts = noteManager.getCurrentNoteCounts(objIds, commentType);
		assertEquals(Integer.valueOf(1), currentCounts.get(fileOne.getId()));
		assertEquals(Integer.valueOf(1), currentCounts.get(fileTwo.getId()));

		// The badge count and the list behind it have to agree, retractions included.
		// Whether a retraction is shown is the consumer's ruling, not this manager's.
		noteManager.deleteNote(revised.getOriginalNoteId(), NoteManager.DeleteMode.SOFT);
		assertEquals(noteManager.getCurrentNotes(fileOne.getId(), commentType).size(),
				(int) noteManager.getCurrentNoteCounts(objIds, commentType).get(fileOne.getId()));

		List<Note> summaries = noteManager.getNotesForDataSource(image.getId(), summaryType);
		assertTrue(summaries.stream().anyMatch(note -> note.getObjectId() == fileTwo.getId()));
	}

	/**
	 * The reasoning behind a finding lives in the note and the score lives in
	 * the analysis result, linked both ways. The attribute holds the note's
	 * stable id rather than a revision id, so it still resolves to the live
	 * text after the note is edited.
	 */
	@Test
	public void analysisResultLinkTest() throws TskCoreException, Blackboard.BlackboardException {
		NoteManager noteManager = caseDB.getNoteManager();
		AbstractFile file = addFile("finding.txt");

		AnalysisResultAdded added = file.newAnalysisResult(
				new BlackboardArtifact.Type(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT),
				Score.SCORE_LIKELY_NOTABLE, "Suspicious executable", "", "", Collections.emptyList());
		AnalysisResult result = added.getAnalysisResult();

		Note note = noteManager.addNote(new NoteRequest(file.getId(), summaryType,
				"Signed by an unknown publisher and launched from a temp folder",
				"{\"mitre\":[\"T1204\"]}", MODEL, null, result.getId(), null));
		assertEquals(Long.valueOf(result.getId()), note.getAnalysisResultId().orElse(null));

		result.addAttribute(new BlackboardAttribute(BlackboardAttribute.Type.TSK_NOTE_ID, MODULE_NAME, note.getOriginalNoteId()));

		// Revising the note must not invalidate the attribute.
		noteManager.reviseNote(note.getNoteId(), "Also seen contacting a known bad host", null,
				new Note.Author(Note.AuthorKind.AI, MODEL.getId(), MODEL.getDisplayName(), "prompt-v2"));

		AnalysisResult reread = caseDB.getBlackboard().getAnalysisResultById(result.getId());
		BlackboardAttribute noteAttribute = reread.getAttribute(BlackboardAttribute.Type.TSK_NOTE_ID);
		Optional<Note> resolved = noteManager.getCurrentRevision(noteAttribute.getValueLong());
		assertTrue(resolved.isPresent());
		assertEquals("Also seen contacting a known bad host", resolved.get().getBody());

		// A note about a finding is anchored on it and has no analysis result of its
		// own; a note explaining the finding is the other way round.
		Note comment = noteManager.addNote(new NoteRequest(result.getId(), commentType, "I disagree with this", ANALYST));
		assertFalse(comment.getAnalysisResultId().isPresent());
		assertEquals(1, noteManager.getNotes(result.getId(), commentType).size());
	}

	/**
	 * A case level note hangs from the case object, which is a root level
	 * object with no parent and therefore no data source.
	 */
	@Test
	public void caseObjectTests() throws TskCoreException {
		NoteManager noteManager = caseDB.getNoteManager();

		long caseObjId = caseDB.getCaseObjectId();
		assertTrue("A case object should have been created", caseObjId > 0);

		Note summary = noteManager.addNote(new NoteRequest(caseObjId, summaryType,
				"Two hosts, one confirmed compromise", null, MODEL, null, null, null));
		assertFalse("A case level note has no data source", summary.getDataSourceObjectId().isPresent());
		assertEquals(1, noteManager.getCurrentNotes(caseObjId, summaryType).size());

		// The case object is parentless, so it turns up in the root object query. That
		// query throws on a root type it does not recognise.
		List<Content> roots = caseDB.getRootObjects();
		assertEquals(1, roots.size());
		assertEquals(image.getId(), roots.get(0).getId());

		assertCaseObjectRowCount(caseDB, 1);
	}

	/**
	 * Reopening a case must find the recorded case object rather than making a
	 * second one, since the get-or-create runs on every open and not only at
	 * creation.
	 */
	@Test
	public void caseObjectIsStableAcrossOpensTest() throws Exception {
		String reopenDbPath = newDbPath("NoteApiCaseObjectTest.db");

		SleuthkitCase reopenCase = SleuthkitCase.newCase(reopenDbPath);
		long originalId;
		try {
			originalId = reopenCase.getCaseObjectId();
			assertTrue(originalId > 0);
		} finally {
			reopenCase.close();
		}

		reopenCase = SleuthkitCase.openCase(reopenDbPath);
		try {
			assertEquals(originalId, reopenCase.getCaseObjectId());
			assertCaseObjectRowCount(reopenCase, 1);
		} finally {
			reopenCase.close();
		}
	}

	/**
	 * Opening a 9.8 case must add the note tables and the case object and leave
	 * a database that behaves like one created at 9.9. The 9.8 database is made
	 * by taking a new case back apart, which is as close as this test can get
	 * without a build of the older schema.
	 */
	@Test
	public void upgradeFromSchema9dot8Test() throws Exception {
		String upgradeDbPath = newDbPath("NoteApiUpgradeTest.db");

		SleuthkitCase newCase = SleuthkitCase.newCase(upgradeDbPath);
		newCase.close();

		try (java.sql.Connection connection = java.sql.DriverManager.getConnection("jdbc:sqlite:" + upgradeDbPath);
				Statement s = connection.createStatement()) {

			s.executeUpdate("DROP TABLE tsk_notes");
			s.executeUpdate("DROP TABLE tsk_note_types");
			s.executeUpdate("DELETE FROM tsk_db_info_extended WHERE name = 'CASE_OBJECT_ID'");
			s.executeUpdate("DELETE FROM tsk_objects WHERE type = " + TskData.ObjectType.CASE.getObjectType());
			s.executeUpdate("UPDATE tsk_db_info SET schema_minor_ver = 8");
			s.executeUpdate("UPDATE tsk_db_info_extended SET value = '8' WHERE name = 'SCHEMA_MINOR_VERSION'");
		}

		SleuthkitCase upgradedCase = SleuthkitCase.openCase(upgradeDbPath);
		try {
			try (SleuthkitCase.CaseDbConnection connection = upgradedCase.getConnection();
					Statement s = connection.createStatement();
					ResultSet rs = s.executeQuery("SELECT schema_ver, schema_minor_ver FROM tsk_db_info")) {
				rs.next();
				assertEquals(9, rs.getInt("schema_ver"));
				assertEquals(9, rs.getInt("schema_minor_ver"));
			} catch (SQLException ex) {
				throw new TskCoreException("Error reading the schema version", ex);
			}

			// The upgraded case has the note tables, the seeded types and a case object,
			// and writing a note through them works the same as on a new case.
			assertCaseObjectRowCount(upgradedCase, 1);
			NoteManager noteManager = upgradedCase.getNoteManager();
			NoteType upgradedCommentType = noteManager.getNoteType(NoteType.BuiltIn.COMMENT.getTypeName()).get();

			Note note = noteManager.addNote(new NoteRequest(upgradedCase.getCaseObjectId(),
					upgradedCommentType, "Written after the upgrade", ANALYST));
			assertEquals(note.getNoteId(), note.getRootNoteId());
			assertEquals(note.getNoteId(), note.getOriginalNoteId());
			assertFalse(note.getDataSourceObjectId().isPresent());

			Note revision = noteManager.reviseNote(note.getNoteId(), "Revised after the upgrade", null, ANALYST);
			assertEquals(note.getOriginalNoteId(), revision.getOriginalNoteId());
			assertEquals(1, noteManager.getCurrentNotes(upgradedCase.getCaseObjectId(), upgradedCommentType).size());
		} finally {
			upgradedCase.close();
		}
	}

	/**
	 * Make a path for a scratch case database, removing any file left behind by
	 * an earlier run.
	 */
	private static String newDbPath(String fileName) {
		String path = Paths.get(System.getProperty("java.io.tmpdir"), fileName).toString();
		new java.io.File(path).delete();
		return path;
	}

	/**
	 * Assert that the case has exactly the expected number of case objects, and
	 * that the recorded id names one of them.
	 */
	private static void assertCaseObjectRowCount(SleuthkitCase skCase, int expected) throws TskCoreException {
		try (SleuthkitCase.CaseDbConnection connection = skCase.getConnection();
				Statement s = connection.createStatement()) {

			try (ResultSet rs = s.executeQuery("SELECT COUNT(*) AS count FROM tsk_objects WHERE type = "
					+ TskData.ObjectType.CASE.getObjectType() + " AND par_obj_id IS NULL")) {
				rs.next();
				assertEquals(expected, rs.getInt("count"));
			}

			try (ResultSet rs = s.executeQuery("SELECT value FROM tsk_db_info_extended WHERE name = 'CASE_OBJECT_ID'")) {
				assertTrue("CASE_OBJECT_ID should be recorded", rs.next());
				assertEquals(skCase.getCaseObjectId(), Long.parseLong(rs.getString("value")));
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error counting case objects", ex);
		}
	}

	/**
	 * Assert that two notes are the same row.
	 */
	private static void assertNoteEquals(Note expected, Note actual) {
		assertEquals(expected.getNoteId(), actual.getNoteId());
		assertEquals(expected.getObjectId(), actual.getObjectId());
		assertEquals(expected.getDataSourceObjectId(), actual.getDataSourceObjectId());
		assertEquals(expected.getType().getNoteTypeId(), actual.getType().getNoteTypeId());
		assertEquals(expected.getBody(), actual.getBody());
		assertEquals(expected.getDetails(), actual.getDetails());
		assertEquals(expected.getAuthor(), actual.getAuthor());
		assertEquals(expected.getCreatedTime(), actual.getCreatedTime());
		assertEquals(expected.getParentNoteId(), actual.getParentNoteId());
		assertEquals(expected.getRootNoteId(), actual.getRootNoteId());
		assertEquals(expected.getOriginalNoteId(), actual.getOriginalNoteId());
		assertEquals(expected.isCurrent(), actual.isCurrent());
		assertEquals(expected.isDeleted(), actual.isDeleted());
		assertEquals(expected.getAnalysisResultId(), actual.getAnalysisResultId());
	}

	/**
	 * Add a file to annotate.
	 */
	private static AbstractFile addFile(String name) throws TskCoreException {
		SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();
		try {
			FsContent file = caseDB.addFileSystemFile(image.getId(), fs.getId(), name, 0, 0,
					TskData.TSK_FS_ATTR_TYPE_ENUM.TSK_FS_ATTR_TYPE_DEFAULT, 0, TskData.TSK_FS_NAME_FLAG_ENUM.ALLOC,
					(short) 0, 200, 0, 0, 0, 0, null, null, null, false, fs, null, null, new ArrayList<>(), trans);
			trans.commit();
			trans = null;
			return file;
		} finally {
			if (trans != null) {
				trans.rollback();
			}
		}
	}
}
