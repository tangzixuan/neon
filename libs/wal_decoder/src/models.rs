//! This module houses types which represent decoded PG WAL records
//! ready for the pageserver to interpret. They are derived from the original
//! WAL records, so that each struct corresponds closely to one WAL record of
//! a specific kind. They contain the same information as the original WAL records,
//! but the values are already serialized in a [`SerializedValueBatch`], which
//! is the format that the pageserver is expecting them in.
//!
//! The ingestion code uses these structs to help with parsing the WAL records,
//! and it splits them into a stream of modifications to the key-value pairs that
//! are ultimately stored in delta layers.  See also the split-out counterparts in
//! [`postgres_ffi::walrecord`].
//!
//! The pipeline which processes WAL records is not super obvious, so let's follow
//! the flow of an example XACT_COMMIT Postgres record:
//!
//! (Postgres XACT_COMMIT record)
//! |
//! |--> pageserver::walingest::WalIngest::decode_xact_record
//!      |
//!      |--> ([`XactRecord::Commit`])
//!           |
//!           |--> pageserver::walingest::WalIngest::ingest_xact_record
//!                |
//!                |--> (NeonWalRecord::ClogSetCommitted)
//!                     |
//!                     |--> write to KV store within the pageserver

use bytes::Bytes;
use pageserver_api::reltag::{RelTag, SlruKind};
use postgres_ffi::walrecord::{
    XlMultiXactCreate, XlMultiXactTruncate, XlRelmapUpdate, XlReploriginDrop, XlReploriginSet,
    XlSmgrTruncate, XlXactParsedRecord,
};
use postgres_ffi::{Oid, TransactionId};
use serde::{Deserialize, Serialize};
use utils::lsn::Lsn;

use crate::serialized_batch::SerializedValueBatch;

#[derive(Serialize, Deserialize)]
pub enum FlushUncommittedRecords {
    Yes,
    No,
}

/// An interpreted Postgres WAL record, ready to be handled by the pageserver
#[derive(Serialize, Deserialize)]
pub struct InterpretedWalRecord {
    /// Optional metadata record - may cause writes to metadata keys
    /// in the storage engine
    pub metadata_record: Option<MetadataRecord>,
    /// A pre-serialized batch along with the required metadata for ingestion
    /// by the pageserver
    pub batch: SerializedValueBatch,
    /// Byte offset within WAL for the end of the original PG WAL record
    pub end_lsn: Lsn,
    /// Whether to flush all uncommitted modifications to the storage engine
    /// before ingesting this record. This is currently only used for legacy PG
    /// database creations which read pages from a template database. Such WAL
    /// records require reading data blocks while ingesting, hence the need to flush.
    pub flush_uncommitted: FlushUncommittedRecords,
    /// Transaction id of the original PG WAL record
    pub xid: TransactionId,
}

/// The interpreted part of the Postgres WAL record which requires metadata
/// writes to the underlying storage engine.
#[derive(Serialize, Deserialize)]
pub enum MetadataRecord {
    Heapam(HeapamRecord),
    Neonrmgr(NeonrmgrRecord),
    Smgr(SmgrRecord),
    Dbase(DbaseRecord),
    Clog(ClogRecord),
    Xact(XactRecord),
    MultiXact(MultiXactRecord),
    Relmap(RelmapRecord),
    Xlog(XlogRecord),
    LogicalMessage(LogicalMessageRecord),
    Standby(StandbyRecord),
    Replorigin(ReploriginRecord),
}

#[derive(Serialize, Deserialize)]
pub enum HeapamRecord {
    ClearVmBits(ClearVmBits),
}

#[derive(Serialize, Deserialize)]
pub struct ClearVmBits {
    pub new_heap_blkno: Option<u32>,
    pub old_heap_blkno: Option<u32>,
    pub vm_rel: RelTag,
    pub flags: u8,
}

#[derive(Serialize, Deserialize)]
pub enum NeonrmgrRecord {
    ClearVmBits(ClearVmBits),
}

#[derive(Serialize, Deserialize)]
pub enum SmgrRecord {
    Create(SmgrCreate),
    Truncate(XlSmgrTruncate),
}

#[derive(Serialize, Deserialize)]
pub struct SmgrCreate {
    pub rel: RelTag,
}

#[derive(Serialize, Deserialize)]
pub enum DbaseRecord {
    Create(DbaseCreate),
    Drop(DbaseDrop),
}

#[derive(Serialize, Deserialize)]
pub struct DbaseCreate {
    pub db_id: Oid,
    pub tablespace_id: Oid,
    pub src_db_id: Oid,
    pub src_tablespace_id: Oid,
}

#[derive(Serialize, Deserialize)]
pub struct DbaseDrop {
    pub db_id: Oid,
    pub tablespace_ids: Vec<Oid>,
}

#[derive(Serialize, Deserialize)]
pub enum ClogRecord {
    ZeroPage(ClogZeroPage),
    Truncate(ClogTruncate),
}

#[derive(Serialize, Deserialize)]
pub struct ClogZeroPage {
    pub segno: u32,
    pub rpageno: u32,
}

#[derive(Serialize, Deserialize)]
pub struct ClogTruncate {
    pub pageno: u32,
    pub oldest_xid: TransactionId,
    pub oldest_xid_db: Oid,
}

#[derive(Serialize, Deserialize)]
pub enum XactRecord {
    Commit(XactCommon),
    Abort(XactCommon),
    CommitPrepared(XactCommon),
    AbortPrepared(XactCommon),
    Prepare(XactPrepare),
}

#[derive(Serialize, Deserialize)]
pub struct XactCommon {
    pub parsed: XlXactParsedRecord,
    pub origin_id: u16,
    // Fields below are only used for logging
    pub xl_xid: TransactionId,
    pub lsn: Lsn,
}

#[derive(Serialize, Deserialize)]
pub struct XactPrepare {
    pub xl_xid: TransactionId,
    pub data: Bytes,
}

#[derive(Serialize, Deserialize)]
pub enum MultiXactRecord {
    ZeroPage(MultiXactZeroPage),
    Create(XlMultiXactCreate),
    Truncate(XlMultiXactTruncate),
}

#[derive(Serialize, Deserialize)]
pub struct MultiXactZeroPage {
    pub slru_kind: SlruKind,
    pub segno: u32,
    pub rpageno: u32,
}

#[derive(Serialize, Deserialize)]
pub enum RelmapRecord {
    Update(RelmapUpdate),
}

#[derive(Serialize, Deserialize)]
pub struct RelmapUpdate {
    pub update: XlRelmapUpdate,
    pub buf: Bytes,
}

#[derive(Serialize, Deserialize)]
pub enum XlogRecord {
    Raw(RawXlogRecord),
}

#[derive(Serialize, Deserialize)]
pub struct RawXlogRecord {
    pub info: u8,
    pub lsn: Lsn,
    pub buf: Bytes,
}

#[derive(Serialize, Deserialize)]
pub enum LogicalMessageRecord {
    Put(PutLogicalMessage),
    #[cfg(feature = "testing")]
    Failpoint,
}

#[derive(Serialize, Deserialize)]
pub struct PutLogicalMessage {
    pub path: String,
    pub buf: Bytes,
}

#[derive(Serialize, Deserialize)]
pub enum StandbyRecord {
    RunningXacts(StandbyRunningXacts),
}

#[derive(Serialize, Deserialize)]
pub struct StandbyRunningXacts {
    pub oldest_running_xid: TransactionId,
}

#[derive(Serialize, Deserialize)]
pub enum ReploriginRecord {
    Set(XlReploriginSet),
    Drop(XlReploriginDrop),
}
