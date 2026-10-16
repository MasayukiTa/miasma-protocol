//! Wire round-trip for the stored-share list/delete control requests, and the
//! compatibility rule that an older daemon does not understand them.

use miasma_core::store::{ShareSelection, StoredShare};
use miasma_core::{ControlRequest, ControlResponse};

#[test]
fn storage_requests_round_trip_through_json() {
    let list = ControlRequest::StorageList;
    let s = serde_json::to_string(&list).unwrap();
    assert_eq!(s, "\"StorageList\"");
    assert!(matches!(
        serde_json::from_str::<ControlRequest>(&s).unwrap(),
        ControlRequest::StorageList
    ));

    let by_id = ControlRequest::StorageDelete {
        selection: ShareSelection::Ids(vec!["deadbeef".into()]),
    };
    let s = serde_json::to_string(&by_id).unwrap();
    match serde_json::from_str::<ControlRequest>(&s).unwrap() {
        ControlRequest::StorageDelete { selection } => {
            assert_eq!(selection, ShareSelection::Ids(vec!["deadbeef".into()]));
        }
        other => panic!("wrong variant: {other:?}"),
    }

    for selection in [ShareSelection::All, ShareSelection::OlderThanDays(30)] {
        let expected = selection.clone();
        let req = ControlRequest::StorageDelete { selection };
        let s = serde_json::to_string(&req).unwrap();
        match serde_json::from_str::<ControlRequest>(&s).unwrap() {
            ControlRequest::StorageDelete { selection: back } => assert_eq!(back, expected),
            other => panic!("wrong variant: {other:?}"),
        }
    }
}

#[test]
fn storage_responses_round_trip_through_json() {
    let listed = ControlResponse::StorageList {
        shares: vec![StoredShare {
            id: "deadbeef".into(),
            address: "deadbeefdeadbeefdeadbeefdeadbeef".into(),
            size_bytes: 4096,
            modified_secs: 1_700_000_000,
            in_use: true,
        }],
        total_bytes: 4096,
    };
    let s = serde_json::to_string(&listed).unwrap();
    match serde_json::from_str::<ControlResponse>(&s).unwrap() {
        ControlResponse::StorageList {
            shares,
            total_bytes,
        } => {
            assert_eq!(total_bytes, 4096);
            assert_eq!(shares.len(), 1);
            assert_eq!(shares[0].id, "deadbeef");
            assert!(shares[0].in_use);
        }
        other => panic!("wrong variant: {other:?}"),
    }

    let deleted = ControlResponse::StorageDeleted {
        deleted: 2,
        freed_bytes: 8192,
        skipped: vec!["cafebabe".into()],
    };
    let s = serde_json::to_string(&deleted).unwrap();
    match serde_json::from_str::<ControlResponse>(&s).unwrap() {
        ControlResponse::StorageDeleted {
            deleted,
            freed_bytes,
            skipped,
        } => {
            assert_eq!(deleted, 2);
            assert_eq!(freed_bytes, 8192);
            assert_eq!(skipped, vec!["cafebabe".to_string()]);
        }
        other => panic!("wrong variant: {other:?}"),
    }
}

#[test]
fn an_older_daemon_cannot_parse_the_new_requests() {
    // The request set before storage management existed: just the old variants.
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "PascalCase")]
    #[allow(dead_code)]
    enum BeforeStorage {
        Status,
        TransferList,
    }

    let s = serde_json::to_string(&ControlRequest::StorageList).unwrap();
    assert!(
        serde_json::from_str::<BeforeStorage>(&s).is_err(),
        "an old daemon must not silently accept StorageList"
    );
    let s = serde_json::to_string(&ControlRequest::StorageDelete {
        selection: ShareSelection::All,
    })
    .unwrap();
    assert!(
        serde_json::from_str::<BeforeStorage>(&s).is_err(),
        "an old daemon must not silently accept StorageDelete"
    );
}
