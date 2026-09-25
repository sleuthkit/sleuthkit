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
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
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

	// Backed by real tsk_authors rows, so they are created in setUpClass() once caseDB
	// exists rather than at class load time.
	private static Author ANALYST;
	private static Author OTHER_ANALYST;
	private static Author MODEL;

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

			AuthorManager authorManager = caseDB.getAuthorManager();
			ANALYST = authorManager.getOrCreateAuthor(TskData.TSK_AUTHOR_TYPE_ENUM.USER, "user-1", "Alice Analyst");
			OTHER_ANALYST = authorManager.getOrCreateAuthor(TskData.TSK_AUTHOR_TYPE_ENUM.USER, "user-2", "Bob Analyst");
			MODEL = authorManager.getOrCreateAuthor(TskData.TSK_AUTHOR_TYPE_ENUM.AI, "model-1", "Some Model");

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

		assertTrue(noteTypeRowCount(caseDB) >= NoteType.BuiltIn.values().length + 1);
	}

	/**
	 * A note on a file records what the caller gave it, and the manager fills
	 * in the columns the caller does not supply: the data source, and the self
	 * references that make it its own thread root and its own first version.
	 */
	@Test
	public void addNoteTests() throws TskCoreException {
		AbstractFile file = addFile("addNote.txt");

		Note note = addNote(caseDB, new NewNoteRequest(file.getId(), commentType,
				"Looks like a dropper", "{\"priority\":\"HIGH\"}", ANALYST, null, null, null, null));

		assertEquals(file.getId(), note.getObjectId());
		assertEquals("Looks like a dropper", note.getBody());
		assertEquals("{\"priority\":\"HIGH\"}", note.getDetails().orElse(null));
		assertEquals(ANALYST, note.getAuthor());
		assertEquals(TskData.TSK_AUTHOR_TYPE_ENUM.USER, note.getAuthor().getType());
		assertFalse(note.getConfiguration().isPresent());
		assertTrue(note.isCurrent());
		assertFalse(note.isDeleted());

		// Derived by the manager, not passed in.
		assertEquals(Long.valueOf(image.getId()), note.getDataSourceObjectId().orElse(null));
		assertEquals(note.getNoteId(), note.getRootNoteId());
		assertEquals(note.getNoteId(), note.getOriginalNoteId());

		// What was written is what comes back.
		List<Note> read = notesOn(caseDB, file.getId());
		assertEquals(1, read.size());
		assertNoteEquals(note, read.get(0));

		// An AI note carries the prompt version, so a bad answer can be told from an old one.
		Note aiNote = addNote(caseDB, new NewNoteRequest(file.getId(), summaryType, "Nothing notable",
				null, MODEL, "prompt-v1", null, null, null));
		assertEquals(TskData.TSK_AUTHOR_TYPE_ENUM.AI, aiNote.getAuthor().getType());
		assertEquals("prompt-v1", aiNote.getConfiguration().orElse(null));

		assertEquals(2, notesOn(caseDB, file.getId()).size());
		assertEquals(1, notesOn(caseDB, file.getId(), commentType).size());
	}

	/**
	 * A reply joins its parent's thread and reads back with it in one query. A
	 * reply on a different object is rejected, so a thread cannot span objects.
	 */
	@Test
	public void threadTests() throws TskCoreException {
		AbstractFile file = addFile("thread.txt");
		AbstractFile otherFile = addFile("threadOther.txt");

		Note root = addNote(caseDB, new NewNoteRequest(file.getId(), commentType, "Is this expected?", ANALYST));
		Note reply = addNote(caseDB, new NewNoteRequest(file.getId(), commentType, "No, it is not",
				null, OTHER_ANALYST, null, root.getNoteId(), null, null));
		Note replyToReply = addNote(caseDB, new NewNoteRequest(file.getId(), commentType, "Agreed",
				null, ANALYST, null, reply.getNoteId(), null, null));

		assertEquals(root.getNoteId(), reply.getRootNoteId());
		assertEquals(root.getNoteId(), replyToReply.getRootNoteId());
		assertEquals(Long.valueOf(reply.getNoteId()), replyToReply.getParentNoteId().orElse(null));

		// A reply is its own first version, even though it is not its own root.
		assertEquals(reply.getNoteId(), reply.getOriginalNoteId());

		List<Note> thread = thread(caseDB, root.getNoteId());
		assertEquals(3, thread.size());
		assertEquals(root.getNoteId(), thread.get(0).getNoteId());

		try {
			addNote(caseDB, new NewNoteRequest(otherFile.getId(), commentType, "Wrong object",
					null, ANALYST, null, root.getNoteId(), null, null));
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
		AbstractFile file = addFile("revise.txt");

		Note first = addNote(caseDB, new NewNoteRequest(file.getId(), commentType, "First draft", ANALYST));
		Note second = reviseNote(caseDB, first.getNoteId(), "Second draft", "{\"v\":2}", null, ANALYST);

		assertNotEquals(first.getNoteId(), second.getNoteId());
		assertEquals(first.getOriginalNoteId(), second.getOriginalNoteId());
		assertEquals(first.getRootNoteId(), second.getRootNoteId());
		assertTrue(second.isCurrent());

		Optional<Note> current = currentRevision(caseDB, first.getOriginalNoteId());
		assertTrue(current.isPresent());
		assertEquals(second.getNoteId(), current.get().getNoteId());
		assertEquals("Second draft", current.get().getBody());

		// The broad read hands back both drafts; the narrow one hands back the live text.
		List<Note> revisions = revisions(caseDB, first.getOriginalNoteId());
		assertEquals(2, revisions.size());
		assertEquals(first.getNoteId(), revisions.get(0).getNoteId());
		assertFalse(revisions.get(0).isCurrent());

		List<Note> currentNotes = currentNotesOn(caseDB, file.getId(), commentType);
		assertEquals(1, currentNotes.size());
		assertEquals("Second draft", currentNotes.get(0).getBody());

		// A model revising its own summary is the same author with a newer prompt.
		Note summary = addNote(caseDB, new NewNoteRequest(file.getId(), summaryType, "Nothing yet", MODEL));
		Note regenerated = reviseNote(caseDB, summary.getNoteId(), "One notable item", null, "prompt-v2", MODEL);
		assertEquals("prompt-v2", regenerated.getConfiguration().orElse(null));

		// A superseded revision is not the one to revise.
		try {
			reviseNote(caseDB, first.getNoteId(), "Too late", null, null, ANALYST);
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
		AbstractFile file = addFile("author.txt");

		Note note = addNote(caseDB, new NewNoteRequest(file.getId(), commentType, "Mine", ANALYST));
		try {
			reviseNote(caseDB, note.getNoteId(), "Not yours to edit", null, null, OTHER_ANALYST);
			fail("Expected revising another author's note to be rejected");
		} catch (TskCoreException ex) {
			assertTrue(ex.getMessage().contains("different author"));
		}

		// The name space is not split by type, so a model that happens to share the
		// analyst's name is still a different author.
		try {
			Author modelWithAnalystName = caseDB.getAuthorManager().getOrCreateAuthor(
					TskData.TSK_AUTHOR_TYPE_ENUM.AI, ANALYST.getName(), "Some Model");
			reviseNote(caseDB, note.getNoteId(), "Not yours either", null, null, modelWithAnalystName);
			fail("Expected revising under a different author type to be rejected");
		} catch (TskCoreException ex) {
			assertTrue(ex.getMessage().contains("different author"));
		}

		// Nothing was written.
		assertEquals(1, revisions(caseDB, note.getOriginalNoteId()).size());
		assertEquals("Mine", currentRevision(caseDB, note.getOriginalNoteId()).get().getBody());
	}

	/**
	 * The revision flip is a check-then-act with no lock behind it on
	 * PostgreSQL, so it is settled by a constraint instead. Two current
	 * revisions of one note have to be impossible rather than merely unlikely.
	 */
	@Test
	public void uniqueIndexRejectsASecondCurrentRevisionTest() throws TskCoreException {
		AbstractFile file = addFile("concurrent.txt");

		Note first = addNote(caseDB, new NewNoteRequest(file.getId(), commentType, "First", ANALYST));
		reviseNote(caseDB, first.getNoteId(), "Second", null, null, ANALYST);

		// Stand in for a second writer that flipped is_current without noticing the
		// first one had already done it.
		try (SleuthkitCase.CaseDbConnection connection = caseDB.getConnection();
				Statement s = connection.createStatement()) {

			s.executeUpdate("UPDATE tsk_notes SET is_current = 1 WHERE note_id = " + first.getNoteId());
			fail("Expected the unique index to reject a second current revision");
		} catch (SQLException ex) {
			// Expected.
		}

		assertEquals(1, currentNotesOn(caseDB, file.getId(), commentType).size());
	}

	/**
	 * A note written in a batch of several must be indistinguishable from one
	 * written in a batch of one on the columns the manager derives. That is the
	 * whole reason the self references are back-filled rather than
	 * pre-allocated.
	 */
	@Test
	public void batchAndSingleParityTest() throws TskCoreException {
		NoteManager noteManager = caseDB.getNoteManager();
		AbstractFile file = addFile("parity.txt");

		Note single = addNote(caseDB, new NewNoteRequest(file.getId(), commentType, "Written one at a time", ANALYST));

		SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();
		List<Note> batch;
		try {
			batch = noteManager.addNotes(Arrays.asList(
					new NewNoteRequest(file.getId(), commentType, "Written in a batch", ANALYST),
					new NewNoteRequest(file.getId(), commentType, "Also in the batch", ANALYST)), trans);
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
			assertNoteEquals(note, noteById(caseDB, note.getNoteId()).get());
		}

		// A reply written in a batch inherits its parent's thread the same way a reply
		// written on its own does.
		trans = caseDB.beginTransaction();
		List<Note> replies;
		try {
			replies = noteManager.addNotes(Collections.singletonList(
					new NewNoteRequest(file.getId(), commentType, "Batched reply", null, ANALYST, null, single.getNoteId(), null, null)), trans);
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
	 * A multi-row INSERT returns its generated ids in whatever order the engine
	 * emits them, so check that a batch comes back matched to the requests that
	 * produced it: same order, same values, each note its own thread root.
	 */
	@Test
	public void batchedInsertPathTest() throws TskCoreException {
		NoteManager noteManager = caseDB.getNoteManager();
		AbstractFile file = addFile("batchedPath.txt");

		List<NewNoteRequest> requests = new ArrayList<>();
		for (int i = 0; i < 5; i++) {
			requests.add(new NewNoteRequest(file.getId(), commentType, "Note " + i,
					"{\"i\":" + i + "}", ANALYST, null, null, null, 1700000000000L + i));
		}

		SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();
		List<Note> batched;
		try {
			batched = noteManager.addNotes(requests, trans);
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
			assertNoteEquals(note, noteById(caseDB, note.getNoteId()).get());
		}

		// A reply written in a batch picks up its parent's thread just as one
		// written in a batch of its own does.
		trans = caseDB.beginTransaction();
		try {
			List<Note> reply = noteManager.addNotes(Collections.singletonList(
					new NewNoteRequest(file.getId(), commentType, "Batched reply", null, ANALYST, null, batched.get(0).getNoteId(), null, null)),
					trans);
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
		AbstractFile file = addFile("delete.txt");

		Note root = addNote(caseDB, new NewNoteRequest(file.getId(), commentType, "Retract me", ANALYST));
		Note reply = addNote(caseDB, new NewNoteRequest(file.getId(), commentType, "Replying",
				null, OTHER_ANALYST, null, root.getNoteId(), null, null));

		deleteNote(caseDB, root.getNoteId(), NoteManager.DeleteMode.SOFT);
		List<Note> afterSoftDelete = thread(caseDB, root.getNoteId());
		assertEquals(2, afterSoftDelete.size());
		assertTrue(afterSoftDelete.get(0).isDeleted());
		assertFalse("A soft delete must not touch the replies", afterSoftDelete.get(1).isDeleted());

		// A retraction stands. Revising the note would otherwise write a row that takes
		// the is_deleted default and quietly bring it back.
		try {
			reviseNote(caseDB, root.getNoteId(), "Actually, let me rephrase", null, null, ANALYST);
			fail("Expected revising a deleted note to be rejected");
		} catch (TskCoreException ex) {
			assertTrue(ex.getMessage().contains("has been deleted"));
		}
		assertTrue(currentRevision(caseDB, root.getOriginalNoteId()).get().isDeleted());

		// Revise the reply first: the cascade has to take a reply that is several rows,
		// whose later revisions reference its first one.
		Note revisedReply = reviseNote(caseDB, reply.getNoteId(), "Replying, more carefully", null, null, OTHER_ANALYST);
		addNote(caseDB, new NewNoteRequest(file.getId(), commentType, "Reply to the reply",
				null, ANALYST, null, revisedReply.getNoteId(), null, null));

		deleteNote(caseDB, root.getNoteId(), NoteManager.DeleteMode.HARD);
		assertTrue(thread(caseDB, root.getNoteId()).isEmpty());
		assertFalse(noteById(caseDB, reply.getNoteId()).isPresent());
		assertTrue(revisions(caseDB, reply.getOriginalNoteId()).isEmpty());

		// A revised note is more than one row, and a hard delete has to take all of
		// them: the later revisions reference the first.
		Note revised = addNote(caseDB, new NewNoteRequest(file.getId(), commentType, "First", ANALYST));
		reviseNote(caseDB, revised.getNoteId(), "Second", null, null, ANALYST);
		deleteNote(caseDB, revised.getNoteId(), NoteManager.DeleteMode.HARD);
		assertTrue(revisions(caseDB, revised.getOriginalNoteId()).isEmpty());

		assertTrue(notesOn(caseDB, file.getId()).isEmpty());
	}

	/**
	 * Both delete modes work on the whole revision lineage, so a consumer
	 * holding the stable original note id - which is what an analysis result's
	 * TSK_ASSOCIATED_NOTE_ID attribute carries - retracts the note the reader can see, not
	 * just the draft that id happens to name.
	 */
	@Test
	public void deleteByOriginalNoteIdTest() throws TskCoreException {
		AbstractFile file = addFile("deleteByOriginal.txt");

		Note first = addNote(caseDB, new NewNoteRequest(file.getId(), commentType, "First", ANALYST));
		Note second = reviseNote(caseDB, first.getNoteId(), "Second", null, null, ANALYST);
		assertNotEquals("The stable id names the superseded draft after a revision",
				first.getOriginalNoteId(), second.getNoteId());

		deleteNote(caseDB, first.getOriginalNoteId(), NoteManager.DeleteMode.SOFT);

		for (Note revision : revisions(caseDB, first.getOriginalNoteId())) {
			assertTrue("Every revision in the lineage should be marked deleted", revision.isDeleted());
		}
		assertTrue(currentRevision(caseDB, first.getOriginalNoteId()).get().isDeleted());

		deleteNote(caseDB, first.getOriginalNoteId(), NoteManager.DeleteMode.HARD);
		assertTrue(revisions(caseDB, first.getOriginalNoteId()).isEmpty());
	}

	/**
	 * A table of items needs a note count per row without loading any prose.
	 * The broad count includes every revision, matching the broad reads; the
	 * current count is the one a badge wants.
	 */
	@Test
	public void batchReadTests() throws TskCoreException {
		AbstractFile fileOne = addFile("batchReadOne.txt");
		AbstractFile fileTwo = addFile("batchReadTwo.txt");
		AbstractFile fileThree = addFile("batchReadThree.txt");

		Note revised = addNote(caseDB, new NewNoteRequest(fileOne.getId(), commentType, "First", ANALYST));
		reviseNote(caseDB, revised.getNoteId(), "Second", null, null, ANALYST);
		addNote(caseDB, new NewNoteRequest(fileTwo.getId(), commentType, "Only one", ANALYST));
		addNote(caseDB, new NewNoteRequest(fileTwo.getId(), summaryType, "A summary", MODEL));

		List<Long> objIds = Arrays.asList(fileOne.getId(), fileTwo.getId(), fileThree.getId());

		Map<Long, List<Note>> comments = notesOnEach(caseDB, objIds, commentType);
		assertEquals(2, comments.get(fileOne.getId()).size());
		assertEquals(1, comments.get(fileTwo.getId()).size());
		assertFalse("Objects with no note are absent from the map", comments.containsKey(fileThree.getId()));

		Map<Long, Integer> allCounts = noteCounts(caseDB, objIds, commentType);
		assertEquals(Integer.valueOf(2), allCounts.get(fileOne.getId()));
		assertEquals(Integer.valueOf(1), allCounts.get(fileTwo.getId()));

		Map<Long, Integer> currentCounts = currentNoteCountsOf(caseDB, objIds, commentType);
		assertEquals(Integer.valueOf(1), currentCounts.get(fileOne.getId()));
		assertEquals(Integer.valueOf(1), currentCounts.get(fileTwo.getId()));

		// The badge count and the list behind it have to agree, retractions included.
		// Whether a retraction is shown is the consumer's ruling, not this manager's.
		deleteNote(caseDB, revised.getOriginalNoteId(), NoteManager.DeleteMode.SOFT);
		assertEquals(currentNotesOn(caseDB, fileOne.getId(), commentType).size(),
				(int) currentNoteCountsOf(caseDB, objIds, commentType).get(fileOne.getId()));

		List<Note> summaries = notesInDataSource(caseDB, image.getId(), summaryType);
		assertTrue(summaries.stream().anyMatch(note -> note.getObjectId() == fileTwo.getId()));
	}

	/**
	 * A panel showing several kinds of note about each of many items reads them
	 * in one query rather than one per type, and can restrict the read to an
	 * author type so that a model is never shown its own output as evidence.
	 */
	@Test
	public void multiTypeBatchReadTests() throws TskCoreException {
		NoteManager noteManager = caseDB.getNoteManager();
		AbstractFile fileOne = addFile("multiTypeOne.txt");
		AbstractFile fileTwo = addFile("multiTypeTwo.txt");
		AbstractFile fileThree = addFile("multiTypeThree.txt");

		Note revised = addNote(caseDB, new NewNoteRequest(fileOne.getId(), commentType, "First", ANALYST));
		reviseNote(caseDB, revised.getNoteId(), "Second", null, null, ANALYST);
		addNote(caseDB, new NewNoteRequest(fileOne.getId(), summaryType, "A summary", MODEL));
		addNote(caseDB, new NewNoteRequest(fileTwo.getId(), commentType, "Only one", ANALYST));

		List<Long> objIds = Arrays.asList(fileOne.getId(), fileTwo.getId(), fileThree.getId());
		List<NoteType> bothTypes = Arrays.asList(commentType, summaryType);

		// One query covers both types, and supersedes are dropped: the revised comment
		// contributes its current revision only.
		Map<Long, List<Note>> notes = noteManager.getCurrentNotes(objIds, bothTypes, null);
		assertEquals(2, notes.get(fileOne.getId()).size());
		assertEquals(1, notes.get(fileTwo.getId()).size());
		assertFalse("Objects with no note are absent from the map", notes.containsKey(fileThree.getId()));

		Map<Long, Map<NoteType, Integer>> counts = noteManager.getCurrentNoteCounts(objIds, bothTypes, null);
		assertEquals(Integer.valueOf(1), counts.get(fileOne.getId()).get(commentType));
		assertEquals(Integer.valueOf(1), counts.get(fileOne.getId()).get(summaryType));
		assertEquals(Integer.valueOf(1), counts.get(fileTwo.getId()).get(commentType));
		assertFalse("A type with no note is absent from the inner map",
				counts.get(fileTwo.getId()).containsKey(summaryType));
		assertFalse(counts.containsKey(fileThree.getId()));

		// The multi-type count must agree with the multi-type list it counts.
		assertEquals(notes.get(fileOne.getId()).size(),
				counts.get(fileOne.getId()).values().stream().mapToInt(Integer::intValue).sum());

		// Author filter: only the model's note survives, and an object whose notes are
		// all human-written drops out of the map entirely.
		Map<Long, List<Note>> aiOnly = noteManager.getCurrentNotes(objIds, bothTypes,
				Arrays.asList(TskData.TSK_AUTHOR_TYPE_ENUM.AI));
		assertEquals(1, aiOnly.get(fileOne.getId()).size());
		assertEquals(summaryType.getNoteTypeId(), aiOnly.get(fileOne.getId()).get(0).getType().getNoteTypeId());
		assertFalse(aiOnly.containsKey(fileTwo.getId()));

		Map<Long, Map<NoteType, Integer>> userCounts = noteManager.getCurrentNoteCounts(objIds, bothTypes,
				Arrays.asList(TskData.TSK_AUTHOR_TYPE_ENUM.USER));
		assertEquals(Integer.valueOf(1), userCounts.get(fileOne.getId()).get(commentType));
		assertFalse("The model's summary is filtered out", userCounts.get(fileOne.getId()).containsKey(summaryType));

		// An empty collection selects nothing rather than everything, so it is rejected
		// outright instead of quietly widening the read.
		try {
			noteManager.getCurrentNotes(objIds, Collections.<NoteType>emptyList(), null);
			fail("An empty type collection should be rejected");
		} catch (TskCoreException expected) {
		}
		try {
			noteManager.getCurrentNoteCounts(objIds, bothTypes, Collections.<TskData.TSK_AUTHOR_TYPE_ENUM>emptyList());
			fail("An empty author type collection should be rejected");
		} catch (TskCoreException expected) {
		}
	}

	/**
	 * The reasoning behind a finding lives in the note and the score lives in
	 * the analysis result, linked both ways. The attribute holds the note's
	 * stable id rather than a revision id, so it still resolves to the live
	 * text after the note is edited.
	 */
	@Test
	public void analysisResultLinkTest() throws TskCoreException, Blackboard.BlackboardException {
		AbstractFile file = addFile("finding.txt");

		AnalysisResultAdded added = file.newAnalysisResult(
				new BlackboardArtifact.Type(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT),
				Score.SCORE_LIKELY_NOTABLE, "Suspicious executable", "", "", Collections.emptyList());
		AnalysisResult result = added.getAnalysisResult();

		Note note = addNote(caseDB, new NewNoteRequest(file.getId(), summaryType,
				"Signed by an unknown publisher and launched from a temp folder",
				"{\"mitre\":[\"T1204\"]}", MODEL, null, null, result.getId(), null));
		assertEquals(Long.valueOf(result.getId()), note.getAnalysisResultId().orElse(null));

		result.addAttribute(new BlackboardAttribute(BlackboardAttribute.Type.TSK_ASSOCIATED_NOTE_ID, MODULE_NAME, note.getOriginalNoteId()));

		// Revising the note must not invalidate the attribute.
		reviseNote(caseDB, note.getNoteId(), "Also seen contacting a known bad host", null, "prompt-v2", MODEL);

		AnalysisResult reread = caseDB.getBlackboard().getAnalysisResultById(result.getId());
		BlackboardAttribute noteAttribute = reread.getAttribute(BlackboardAttribute.Type.TSK_ASSOCIATED_NOTE_ID);
		Optional<Note> resolved = currentRevision(caseDB, noteAttribute.getValueLong());
		assertTrue(resolved.isPresent());
		assertEquals("Also seen contacting a known bad host", resolved.get().getBody());

		// A note about a finding is anchored on it and has no analysis result of its
		// own; a note explaining the finding is the other way round.
		Note comment = addNote(caseDB, new NewNoteRequest(result.getId(), commentType, "I disagree with this", ANALYST));
		assertFalse(comment.getAnalysisResultId().isPresent());
		assertEquals(1, notesOn(caseDB, result.getId(), commentType).size());
	}

	/**
	 * A case level note hangs from the case object, which is a root level
	 * object with no parent and therefore no data source.
	 */
	@Test
	public void caseObjectTests() throws TskCoreException {
		long caseObjId = caseDB.getCaseObjectId();
		assertTrue("A case object should have been created", caseObjId > 0);

		Note summary = addNote(caseDB, new NewNoteRequest(caseObjId, summaryType,
				"Two hosts, one confirmed compromise", null, MODEL, null, null, null, null));
		assertFalse("A case level note has no data source", summary.getDataSourceObjectId().isPresent());
		assertEquals(1, currentNotesOn(caseDB, caseObjId, summaryType).size());

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
			s.executeUpdate("DROP TABLE tsk_authors");
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

			// A different case database has its own tsk_authors rows, so the author has to
			// be resolved through this case rather than reusing one from caseDB.
			Author upgradedAnalyst = upgradedCase.getAuthorManager().getOrCreateAuthor(
					TskData.TSK_AUTHOR_TYPE_ENUM.USER, "user-1", "Alice Analyst");

			Note note = addNote(upgradedCase, new NewNoteRequest(upgradedCase.getCaseObjectId(),
					upgradedCommentType, "Written after the upgrade", upgradedAnalyst));
			assertEquals(note.getNoteId(), note.getRootNoteId());
			assertEquals(note.getNoteId(), note.getOriginalNoteId());
			assertFalse(note.getDataSourceObjectId().isPresent());

			Note revision = reviseNote(upgradedCase, note.getNoteId(), "Revised after the upgrade", null, null, upgradedAnalyst);
			assertEquals(note.getOriginalNoteId(), revision.getOriginalNoteId());
			assertEquals(1, currentNotesOn(upgradedCase, upgradedCase.getCaseObjectId(), upgradedCommentType).size());
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

	// ------------------------------------------------------------------
	// Row observation
	//
	// NoteManager exposes one read - getCurrentNotes(objIds, types, authorTypes) -
	// because that is the only one a consumer needs today. These tests have to see
	// rows that read does not return: superseded revisions, whole threads, notes by
	// id. They query for them directly, and hydrate through the manager's own
	// getNoteFromResultSet() rather than building Notes here, so a column added to
	// the table cannot quietly go unasserted.
	// ------------------------------------------------------------------
	/**
	 * Run a note query and hydrate the rows.
	 *
	 * @param where A WHERE clause body, without the keyword. Ordering is always
	 *              oldest first, as the manager's own reads are.
	 */
	private static List<Note> query(SleuthkitCase skCase, String where) throws TskCoreException {
		List<Note> notes = new ArrayList<>();
		try (SleuthkitCase.CaseDbConnection connection = skCase.getConnection();
				Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s,
						NoteManager.NOTE_SELECT + "WHERE " + where + NoteManager.NOTE_ORDER)) {

			while (rs.next()) {
				notes.add(NoteManager.getNoteFromResultSet(rs));
			}
			return notes;
		} catch (SQLException ex) {
			throw new TskCoreException("Error reading notes for " + where, ex);
		}
	}

	/** Every note on an object, every type, revisions and retractions included. */
	private static List<Note> notesOn(SleuthkitCase skCase, long objId) throws TskCoreException {
		return query(skCase, "notes.obj_id = " + objId);
	}

	/** Every note of one type on an object, revisions and retractions included. */
	private static List<Note> notesOn(SleuthkitCase skCase, long objId, NoteType type) throws TskCoreException {
		return query(skCase, "notes.obj_id = " + objId + " AND notes.note_type_id = " + type.getNoteTypeId());
	}

	/** The current revisions of one type on an object, retractions included. */
	private static List<Note> currentNotesOn(SleuthkitCase skCase, long objId, NoteType type) throws TskCoreException {
		return query(skCase, "notes.obj_id = " + objId + " AND notes.note_type_id = " + type.getNoteTypeId()
				+ " AND notes.is_current = 1");
	}

	/** Every note of one type anywhere in a data source. */
	private static List<Note> notesInDataSource(SleuthkitCase skCase, long dataSourceObjId, NoteType type)
			throws TskCoreException {
		return query(skCase, "notes.data_source_obj_id = " + dataSourceObjId
				+ " AND notes.note_type_id = " + type.getNoteTypeId());
	}

	/** Every revision of one note, oldest first. */
	private static List<Note> revisions(SleuthkitCase skCase, long originalNoteId) throws TskCoreException {
		return query(skCase, "notes.original_note_id = " + originalNoteId);
	}

	/** The live revision of one note, which the unique index makes at most one. */
	private static Optional<Note> currentRevision(SleuthkitCase skCase, long originalNoteId) throws TskCoreException {
		List<Note> notes = query(skCase, "notes.original_note_id = " + originalNoteId + " AND notes.is_current = 1");
		return notes.isEmpty() ? Optional.empty() : Optional.of(notes.get(0));
	}

	/** A whole thread, oldest first. */
	private static List<Note> thread(SleuthkitCase skCase, long rootNoteId) throws TskCoreException {
		return query(skCase, "notes.root_note_id = " + rootNoteId);
	}

	/** One note by the id of the revision. */
	private static Optional<Note> noteById(SleuthkitCase skCase, long noteId) throws TskCoreException {
		List<Note> notes = query(skCase, "notes.note_id = " + noteId);
		return notes.isEmpty() ? Optional.empty() : Optional.of(notes.get(0));
	}

	/** How many note types the case has, seeded and consumer-added together. */
	private static int noteTypeRowCount(SleuthkitCase skCase) throws TskCoreException {
		try (SleuthkitCase.CaseDbConnection connection = skCase.getConnection();
				Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, "SELECT COUNT(*) AS count FROM tsk_note_types")) {

			rs.next();
			return rs.getInt("count");
		} catch (SQLException ex) {
			throw new TskCoreException("Error counting note types", ex);
		}
	}

	/** Every note of one type on each of many objects, keyed by object. */
	private static Map<Long, List<Note>> notesOnEach(SleuthkitCase skCase, Collection<Long> objIds, NoteType type)
			throws TskCoreException {
		Map<Long, List<Note>> byObject = new HashMap<>();
		for (Long objId : objIds) {
			List<Note> notes = notesOn(skCase, objId, type);
			if (!notes.isEmpty()) {
				byObject.put(objId, notes);
			}
		}
		return byObject;
	}

	/** Note counts of one type per object, revisions and retractions included. */
	private static Map<Long, Integer> noteCounts(SleuthkitCase skCase, Collection<Long> objIds, NoteType type)
			throws TskCoreException {
		Map<Long, Integer> counts = new HashMap<>();
		for (Long objId : objIds) {
			int count = notesOn(skCase, objId, type).size();
			if (count > 0) {
				counts.put(objId, count);
			}
		}
		return counts;
	}

	/** Current-revision counts of one type per object, retractions included. */
	private static Map<Long, Integer> currentNoteCountsOf(SleuthkitCase skCase, Collection<Long> objIds, NoteType type)
			throws TskCoreException {
		Map<Long, Integer> counts = new HashMap<>();
		for (Long objId : objIds) {
			int count = currentNotesOn(skCase, objId, type).size();
			if (count > 0) {
				counts.put(objId, count);
			}
		}
		return counts;
	}

	/**
	 * Revise one note and commit it. The manager's reviseNote() writes as part
	 * of the caller's transaction; these tests have nothing to commit alongside
	 * it, so the transaction is opened here rather than in every test.
	 */
	private static Note reviseNote(SleuthkitCase skCase, long noteId, String body, String details,
			String configuration, Author author) throws TskCoreException {
		SleuthkitCase.CaseDbTransaction trans = skCase.beginTransaction();
		try {
			Note revision = skCase.getNoteManager().reviseNote(noteId, body, details, configuration, author, trans);
			trans.commit();
			trans = null;
			return revision;
		} finally {
			if (trans != null) {
				trans.rollback();
			}
		}
	}

	/** Delete one note, which the manager only offers as a collection. */
	private static void deleteNote(SleuthkitCase skCase, long noteId, NoteManager.DeleteMode mode)
			throws TskCoreException {
		skCase.getNoteManager().deleteNotes(Collections.singletonList(noteId), mode);
	}

	/**
	 * Add one note and commit it.
	 *
	 * NoteManager.addNotes() writes as part of the caller's transaction, which
	 * is the only write it offers: the caller is the one that knows whether a
	 * note belongs with anything else in the same commit. These tests assert on
	 * one note at a time and have nothing to commit alongside it, so the
	 * transaction is opened here rather than in every test.
	 */
	private static Note addNote(SleuthkitCase skCase, NewNoteRequest request) throws TskCoreException {
		SleuthkitCase.CaseDbTransaction trans = skCase.beginTransaction();
		try {
			Note note = skCase.getNoteManager().addNotes(Collections.singletonList(request), trans).get(0);
			trans.commit();
			trans = null;
			return note;
		} finally {
			if (trans != null) {
				trans.rollback();
			}
		}
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
		assertEquals(expected.getConfiguration(), actual.getConfiguration());
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
