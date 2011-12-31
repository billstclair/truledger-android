package com.truledger.client;

import android.content.Context;

public class ClientDB {
	
	private static final String PRIVKEY_DB_NAME = "privkey";
	private static final String PUBKEY_DB_NAME = "pubkey";
	private static final String SERVERID_DB_NAME = "serverid";
	private static final String SERVER_DB_NAME = "server";
	private static final String SESSION_DB_NAME = "session";
	private static final String ACCOUNT_DB_NAME = "account";
	
	/**
	 * Private key database
	 * @author billstclair
	 * Maps hash of passphrase to encrypted private key
	 */
	public class PrivkeyDB extends FSDB {
		public PrivkeyDB(Context ctx) {
			super(ctx, PRIVKEY_DB_NAME);
		}
	}

	/**
	 * Public key database
	 * @author billstclair
	 * Maps account ID to public key
	 */
	public class PubkeyDB extends FSDB {
		public PubkeyDB(Context ctx) {
			super(ctx, PUBKEY_DB_NAME);
		}
	}

	/**
	 * Server ID database
	 * @author billstclair
	 * Maps hash of server URL to server ID
	 */
	public class ServeridDB extends FSDB {
		public ServeridDB(Context ctx) {
			super(ctx, SERVERID_DB_NAME);
		}
		
		public String getUrlID(String url) {
			return this.get(null, Crypto.sha1(url));
		}
		
		public String putUrlID(String url, String id) {
			return this.put(null,  Crypto.sha1(url), id);
		}
	}
	
	/**
	 * Server database
	 * @author billstclair
	 * Maps serverid to a directory containing url, name, tokenid, regfee, tranfee,
	 * features, fee/, asset/, permission/
	 */
	public class ServerDB extends FSDB {
		public ServerDB(Context ctx) {
			super(ctx, SERVER_DB_NAME);
		}
	}

	/**
	 * Session database
	 * @author billstclair
	 * Maps session hash to encrypted passphrase
	 */
	public class SessionDB extends FSDB {
		public SessionDB(Context ctx) {
			super(ctx, SESSION_DB_NAME);
		}
	}

	/**
	 * Account database
	 * @author billstclair
	 * Maps <id> to session, preference, contact/, server/
	 */
	public class AccountDB extends FSDB {
		public AccountDB(Context ctx) {
			super(ctx, ACCOUNT_DB_NAME);
		}
	}
	
	private final Context mCtx;
	
	private PrivkeyDB mPrivkeyDB;
	private PubkeyDB mPubkeyDB;
	private ServeridDB mServeridDB;
	private ServerDB mServerDB;
	private SessionDB mSessionDB;
	private AccountDB mAccountDB;
	
	public ClientDB(Context ctx) {
		this.mCtx = ctx;
	}
	
	public PrivkeyDB getPrivkeyDB() {
		if (mPrivkeyDB == null) {
			mPrivkeyDB = new PrivkeyDB(mCtx);
		}
		return mPrivkeyDB;
	}
	  
	public PubkeyDB getPubkeyDB() {
		if (mPubkeyDB == null) {
			mPubkeyDB = new PubkeyDB(mCtx);
		}
		return mPubkeyDB;
	}
	  
	public ServeridDB getServeridDB() {
		if (mServeridDB == null) {
			mServeridDB = new ServeridDB(mCtx);
		}
		return mServeridDB;
	}
	  
	public ServerDB getServerDB() {
		if (mServerDB == null) {
			mServerDB = new ServerDB(mCtx);
		}
		return mServerDB;
	}
	  
	public SessionDB SessionDB() {
		if (mSessionDB == null) {
			mSessionDB = new SessionDB(mCtx);
		}
		return mSessionDB;
	}
	  
	public AccountDB getAccountDB() {
		if (mAccountDB == null) {
			mAccountDB = new AccountDB(mCtx);
		}
		return mAccountDB;
	}
	  
}
