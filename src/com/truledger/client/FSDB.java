package com.truledger.client;

import java.util.Arrays;
import java.util.Collections;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.SQLException;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

public class FSDB {

	private static final String TOPLEVEL_TABLE_NAME = "dirindex";
	private static final String KEY_TOPLEVEL_ROWID = "_dirid";
	private static final String KEY_TOPLEVEL_DIRPATH = "dirpath";
	
	private static final String DIRECTORY_TABLE_NAME = "dirfiles";
	private static final String KEY_DIRECTORY_ROWID = "_fileid";
	private static final String KEY_DIRECTORY_DIRID = "dirid";
	private static final String KEY_DIRECTORY_FILENAME = "filename";
	
	private static final String VALUE_TABLE_NAME = "contents";
	private static final String KEY_VALUE_ROWID = "_fileid";
	private static final String KEY_VALUE_CONTENTS = "contents";
	
	private DatabaseHelper mDbHelper;
	private SQLiteDatabase mDb;

	/**
	 * Database creation sql statements
	 */
	private static final String TOPLEVEL_TABLE_CREATE =
			"create table dirindex (_dirid integer primary key autoincrement, "
					+ "dirpath text not null);";
	private static final String TOPLEVEL_TABLE_INDEX =
			"create unique index dirpath on dirindex (dirpath);";

	private static final String DIRECTORY_TABLE_CREATE =
			"create table dirfiles " +
			"(_fileid integer primary key autoincrement, dirid integer, filename text not null);";
	private static final String DIRECTORY_TABLE_INDEX1 =
			"create index dirid on dirfiles (dirid);";
	private static final String DIRECTORY_TABLE_INDEX2 =
			"create unique index filename on dirfiles (dirid, filename);";
	
	private static final String VALUE_TABLE_CREATE =
			"create table contents (_fileid integer primary key, contents text not null);";
	
	private static final int DATABASE_VERSION = 2;
	private static final long EMPTY_DIR_INDEX = 1;

	private final Context mCtx;
	private final String dbName;

	private static class DatabaseHelper extends SQLiteOpenHelper {

		DatabaseHelper(Context context, String dbName) {
			super(context, dbName, null, DATABASE_VERSION);
		}

		@Override
		public void onCreate(SQLiteDatabase db) throws SQLException {
			db.execSQL(TOPLEVEL_TABLE_CREATE);
			db.execSQL(TOPLEVEL_TABLE_INDEX);
			db.execSQL(DIRECTORY_TABLE_CREATE);
			db.execSQL(DIRECTORY_TABLE_INDEX1);
			db.execSQL(DIRECTORY_TABLE_INDEX2);
			db.execSQL(VALUE_TABLE_CREATE);
			
			ContentValues initialValues = new ContentValues();
			initialValues.put(KEY_TOPLEVEL_DIRPATH, "");
			long index = db.insert(TOPLEVEL_TABLE_NAME, null, initialValues);
			if (index != EMPTY_DIR_INDEX) {
				throw new SQLException("empty dir index = " + index);
			}
		}

		@Override
		public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
		}
	}

	/**
	 * Constructor - takes the context to allow the database to be
	 * opened/created
	 * 
	 * @param ctx the Context within which to work
	 * @param dbName The name of the database
	 * @throws SQLException If the database could not be opened or created
	 */
	public FSDB(Context ctx, String dbName) throws SQLException {
		this.mCtx = ctx;
		this.dbName = dbName;
		mDbHelper = new DatabaseHelper(mCtx, dbName);
		mDb = mDbHelper.getWritableDatabase();
	}

	/**
	 * Close the database
	 */
	public void close() {
		mDbHelper.close();
	}
	
	public void clearAll() {
		mDb.delete(TOPLEVEL_TABLE_NAME, null, null);
		mDb.delete(DIRECTORY_TABLE_NAME, null, null);
		mDb.delete(VALUE_TABLE_NAME, null, null);
	}
	
	/**
	 * Find the rowid for the toplevel directory entry for dirpath
	 * @param dirpath The path to the directory
	 * @param createIfNot True to create the directory entry if it does not exist
	 * @return The rowid, -1 if there is no row, -rowid - 1 if the row was created.
	 * @throws SQLException if there was an error inserting a new row
	 */
	private long getDirID(String dirpath, boolean createIfNot) throws SQLException {
		if (Utility.isNull(dirpath)) return EMPTY_DIR_INDEX;
		Cursor cursor = mDb.query(TOPLEVEL_TABLE_NAME, new String[] {KEY_TOPLEVEL_ROWID},
				KEY_TOPLEVEL_DIRPATH + "=?", new String[] {dirpath}, null, null, null);
		try {
			if (cursor != null && cursor.getCount() == 1) {
				cursor.moveToFirst();
				long res = cursor.getLong(0);
				return res;
			} 
		} finally {
			if (cursor != null) cursor.close();
		}
		if (createIfNot) {
			ContentValues iv = new ContentValues();
			iv.put(KEY_TOPLEVEL_DIRPATH, dirpath);
			long dirid = mDb.insert(TOPLEVEL_TABLE_NAME, null, iv);
			if (dirid == -1) throw new SQLException("Failed to create toplevel entry for dirpath: " + dirpath);
			return -dirid - 1;
		} else {
			return -1;
		}
	}

	/**
	 * Find the rowid for inserting a value in the VALUE_TABLE_NAME
	 * @param dirpath the directory path
	 * @param filename the file name
	 * @param createIfNot true to create the index if it's not there already
	 * @returns the rowid for insertion, or -1 if there was no such dirpath/filename pair
	 * @throws SQLException if there was an error creating the new dirpath/filename pair
	 */
	private long getFileID(String dirpath, String filename, boolean createIfNot) throws SQLException {
		long dirid = this.getDirID(dirpath, createIfNot);
		if (dirid == -1) return -1;
		boolean isNewDirid = false;
		if (dirid < 0) {
			dirid = -(dirid+1);
			isNewDirid = true;
		}
		Cursor cursor = null;
		if (!isNewDirid) {
			cursor = mDb.query(DIRECTORY_TABLE_NAME,  new String[] {KEY_DIRECTORY_ROWID},
					KEY_DIRECTORY_DIRID + "=" + dirid + " AND " + KEY_DIRECTORY_FILENAME + "=?",
					new String[] {filename}, null, null, null);
		}
		try {
			if (cursor != null && cursor.getCount() == 1) {
				cursor.moveToFirst();
				long res = cursor.getLong(0);
				return res;
			}
		} finally {
			if (cursor != null) cursor.close();
		}
		if (createIfNot) {
			ContentValues iv = new ContentValues();
			iv.put(KEY_DIRECTORY_DIRID, dirid);
			iv.put(KEY_DIRECTORY_FILENAME, filename);
			long fileid = mDb.insert(DIRECTORY_TABLE_NAME, null, iv);
			if (fileid < 0) throw new SQLException("Error inserting into directory table");
			return fileid;			
		} else {
			return -1;
		}
	}
	
	/**
	 * Write a value into the database
	 * 
	 * @param dirpath the directory path for the write
	 * @param filename the file name for the write
	 * @param contents the value to write
	 * @return contents
	 */
	public String put(String dirpath, String filename, String contents) throws SQLException {
		boolean notnull = !Utility.isNull(contents);
		long fileid = this.getFileID(dirpath, filename, notnull);
		String where = KEY_VALUE_ROWID + "=" + fileid;
		if (!notnull) {
			if (fileid >= 0) {
				mDb.delete(VALUE_TABLE_NAME, where, null);
			}
			return contents;
		}
		ContentValues iv = new ContentValues();
		iv.put(KEY_VALUE_CONTENTS, contents);
		if (mDb.update(VALUE_TABLE_NAME, iv, where, null) > 0) {
			return contents;
		}
		iv.put(KEY_VALUE_ROWID, fileid);
		long rowid = mDb.insert(VALUE_TABLE_NAME, null, iv);
		if (rowid == -1) {
			throw new SQLException("Error inserting value into contents table");
		}
		return contents;
	}

	/**
	 * Fetch a database value from dirpath/filename
	 * @param dirpath the path of the directory
	 * @param filename the filename
	 * @return the contents of dirpath/filename, or NULL if there is none.
	 */
	public String get(String dirpath, String filename) {
		long fileid = this.getFileID(dirpath, filename, false);
		if (fileid < 0) return null;
		Cursor cursor = mDb.query(VALUE_TABLE_NAME, new String[] {KEY_VALUE_CONTENTS},
				KEY_VALUE_ROWID + "=" + fileid, null, null, null, null);
		if (cursor == null) return null;
		try {
			if (cursor.getCount() != 1) return null;
			cursor.moveToFirst();
			return cursor.getString(0);
		} finally {
			cursor.close();
		}
	}
	
	/**
	 * Return all the filenames in a directory
	 * @param dirpath the path of the directory
	 * @return an array of filename strings, or NULL if dirpath is empty
	 */
	public String[] contents(String dirpath) {
		long dirid = this.getDirID(dirpath, false);
		if (dirid == -1) return null;
		Cursor cursor = mDb.query(DIRECTORY_TABLE_NAME,  new String[] {KEY_DIRECTORY_FILENAME},
				KEY_DIRECTORY_DIRID + "=" + dirid, null, null, null, null);
		if (cursor == null) return null;
		try {
			int count = cursor.getCount();
			if (count == 0) return null;
			String[] res = new String[count];
			for (int i=0; i<count; i++) {
				cursor.moveToNext();
				res[i] = cursor.getString(0);
			}
			Arrays.sort(res);
			return res;
		} finally {
			cursor.close();
		}
	}

	public String getDbName() {
		return dbName;
	}
}

//////////////////////////////////////////////////////////////////////
///
/// Copyright 2011 Bill St. Clair
///
/// Licensed under the Apache License, Version 2.0 (the "License")
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     http://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions
/// and limitations under the License.
///
//////////////////////////////////////////////////////////////////////
