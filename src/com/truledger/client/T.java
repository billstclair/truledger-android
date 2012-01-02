package com.truledger.client;

/**
 * Tokenize the protocol strings
 * @author billstclair
 */
public class T {
	// db file & directory names
	public static final String TIME = "time";
	public static final String PRIVKEY = "privkey";
	public static final String SERVERID = "serverid";
	public static final String TOKENID = "tokenid";
	public static final String REGFEE = "regfee";
	public static final String TRANFEE = "tranfee";
	public static final String FEE = "fee";
	public static final String PUBKEY = "pubkey";
	public static final String PUBKEYSIG = "pubkeysig";
	public static final String ASSET = "asset";
	public static final String SHUTDOWNMSG = "shutdownmsg";
	public static final String STORAGE = "storage";
	public static final String STORAGEFEE = "storagefee";
	public static final String FRACTION = "fraction";
	public static final String ACCOUNT = "account";
	public static final String LAST = "last";
	public static final String REQ = "req";
	public static final String BALANCE = "balance";
	public static final String MAIN = "main";
	public static final String OUTBOX = "outbox";
	public static final String OUTBOXHASH = "outboxhash";
	public static final String INBOX = "inbox";
	public static final String INBOXIGNORED = "inboxignored";
	public static final String COUPON = "coupon";
	public static final String DATA = "data";
	public static final String BACKUP = "backup";
	public static final String READINDEX = "readindex";
	public static final String WRITEINDEX = "writeindex";
	public static final String WALKINDEX = "walkindex";
	public static final String LASTTRANSACTION = "lasttransaction";

	// request names
	public static final String ID = "id";
	public static final String REGISTER = "register";
	public static final String FAILED = "failed";
	public static final String REASON = "reason";
	public static final String GETREQ = "getreq";
	public static final String GETTIME = "gettime";
	public static final String GETFEES = "getfees";
	public static final String SETFEES = "setfees";
	public static final String TRANSFER = "transfer";
	public static final String SPEND = "spend";
	public static final String GETINBOX = "getinbox";
	public static final String PROCESSINBOX = "processinbox";
	public static final String STORAGEFEES = "storagefees";
	public static final String SPENDACCEPT = "spend|accept";
	public static final String SPENDREJECT = "spend|reject";
	public static final String AFFIRM = "affirm";
	public static final String GETASSET = "getasset";
	public static final String GETOUTBOX = "getoutbox";
	public static final String GETBALANCE = "getbalance";
	public static final String COUPONENVELOPE = "couponenvelope";
	public static final String GETVERSION = "getversion";
	public static final String VERSION = "version";
	public static final String WRITEDATA = "writedata";
	public static final String READDATA = "readdata";
	public static final String GRANT = "grant";
	public static final String DENY = "deny";
	public static final String PERMISSION = "permission";
	public static final String AUDIT = "audit";
	public static final String OPENSESSION = "opensession";
	public static final String CLOSESESSION = "closesession";
	public static final String COMMIT = "commit";
	public static final String GETFEATURES = "getfeatures";
	public static final String FEATURES = "features";

	// Affirmations
	public static final String ATREGISTER = "@register";
	public static final String ATOUTBOXHASH = "@outboxhash";
	public static final String ATSTORAGE = "@storage";
	public static final String ATSTORAGEFEE = "@storagefee";
	public static final String ATFRACTION = "@fraction";
	public static final String ATBALANCE = "@balance";
	public static final String ATSETFEES = "@setfees";
	public static final String ATSPEND = "@spend";
	public static final String ATTRANFEE = "@tranfee";
	public static final String ATFEE = "@fee";
	public static final String ATASSET = "@asset";
	public static final String ATGETINBOX = "@getinbox";
	public static final String ATPROCESSINBOX = "@processinbox";
	public static final String ATSTORAGEFEES = "@storagefees";
	public static final String ATSPENDACCEPT = "@spend|accept";
	public static final String ATSPENDREJECT = "@spend|reject";
	public static final String ATGETOUTBOX = "@getoutbox";
	public static final String ATBALANCEHASH = "@balancehash";
	public static final String ATCOUPON = "@coupon";
	public static final String ATCOUPONENVELOPE = "@couponenvelope";
	public static final String ATWRITEDATA = "@writedata";
	public static final String ATREADDATA = "@readdata";
	public static final String ATGRANT = "@grant";
	public static final String ATDENY = "@deny";
	public static final String ATPERMISSION = "@permission";
	public static final String ATAUDIT = "@audit";
	public static final String ATOPENSESSION = "@opensession";
	public static final String ATCLOSESESSION = "@closesession";
	public static final String ATBACKUP = "@backup";
	public static final String ATCOMMIT = "@commit";

	// request parameter names
	public static final String CUSTOMER = "customer";
	public static final String REQUEST = "request";
	public static final String NAME = "name";
	public static final String NOTE = "note";
	public static final String ACCT = "acct";
	public static final String OPERATION = "operation";
	public static final String TRAN = "tran";
	public static final String AMOUNT = "amount";
	public static final String ASSETNAME = "assetname";
	public static final String SCALE = "scale";
	public static final String PRECISION = "precision";
	public static final String PERCENT = "percent";
	public static final String TIMELIST = "timelist";
	public static final String HASH = "hash";
	public static final String MSG = "msg";
	public static final String ERRMSG = "errmsg";
	public static final String BALANCEHASH = "balancehash";
	public static final String COUNT = "count";
	public static final String SERVERURL = "serverurl";
	public static final String ENCRYPTEDCOUPON = "encryptedcoupon";
	public static final String COUPONNUMBERHASH = "couponnumberhash";
	public static final String ISSUER = "issuer";
	public static final String ANONYMOUS = "anonymous";
	public static final String KEY = "key";
	public static final String SIZE = "size";
	public static final String SESSIONID = "sessionid";
	public static final String CIPHERTEXT = "ciphertext";
	public static final String TIMEOUT = "timeout";
	public static final String INACTIVETIME = "inactivetime";
	public static final String TWOPHASECOMMIT = "twophasecommit";

	// Client database keys
	public static final String SERVER = "server";
	public static final String SERVERS = "servers";
	public static final String URL = "url";
	public static final String NICKNAME = "nickname";
	public static final String CONTACT = "contact";
	public static final String SESSION = "session";
	public static final String PREFERENCE = "preference";
	public static final String TOKEN = "token";
	public static final String HISTORY = "history";
	public static final String PRIVKEYCACHEDP = "privkeycachedp";
	public static final String NEEDPRIVKEYCACHE = "needprivkeycache";
	public static final String LOOM = "loom";
	public static final String SALT = "salt";
	public static final String PASSPHRASE = "passphrase";
	public static final String WALLETNAME = "walletname";
	public static final String WALLET = "wallet";
	public static final String PRIVATE = "private";
	public static final String URLHASH = "urlhash";
	public static final String NAMEHASH = "namehash";

	// Other client tokens
	public static final String FORMATTEDAMOUNT = "formattedamount";
	public static final String MSGTIME = "msgtime";
	public static final String ATREQUEST = "@request";
	public static final String MINT_TOKENS = "mint-tokens";
	public static final String MINT_COUPONS = "mint-coupons";
	public static final String ADD_ASSET = "add-asset";

	// Marker in hash tables
	public static final String UNPACK_REQS_KEY = "unpack-reqs";
}

//////////////////////////////////////////////////////////////////////
///
/// Copyright 2012 Bill St. Clair
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
