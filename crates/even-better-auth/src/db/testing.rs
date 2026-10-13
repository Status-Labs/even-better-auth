//! A conformance suite for [`Adapter`] implementations (cargo feature `testing`).
//!
//! [`run_adapter_suite`] migrates a pair of uniquely named tables, then exercises every
//! operator, sorting, pagination, unique constraints, the write operations,
//! `consume_one` atomicity, transactions (when supported) and type round-trips through
//! [`Db`]. It panics on failure.

use std::sync::Arc;

use serde_json::{Value, json};

use super::{
    Adapter, Db, Field, FieldType, FindManyQuery, IdGenerator, OnDelete, Operator, Record, Schema, SortBy,
    SortDirection, Table, Where,
};

/// The suite's schema: an `owner` table and an `item` table covering every field type.
/// With `extended`, `item` gains `note`, a `level` column with a default and a unique `code`.
pub fn suite_schema(suffix: &str, extended: bool) -> Schema {
    let mut owner = Table::new("owner");
    owner.model_name = format!("ba_owner_{suffix}");
    owner.order = 1;
    owner.fields = vec![("name".into(), Field::string())];

    let mut item = Table::new("item");
    item.model_name = format!("ba_item_{suffix}");
    item.order = 2;
    item.fields = vec![
        ("name".into(), Field::string().sortable()),
        ("email".into(), Field::string().unique()),
        ("age".into(), Field::number()),
        ("score".into(), Field::number().bigint().optional()),
        ("active".into(), Field::boolean().default(false)),
        ("createdAt".into(), Field::date().default_now()),
        ("expiresAt".into(), Field::date().optional()),
        ("meta".into(), Field::json().optional()),
        ("tags".into(), Field::new(FieldType::StringArray).optional()),
        ("nums".into(), Field::new(FieldType::NumberArray).optional()),
        ("nickname".into(), Field::string().optional().field_name("nick_name")),
        ("ownerId".into(), Field::string().optional().references("owner", "id", OnDelete::Cascade).indexed()),
    ];
    if extended {
        item.fields.push(("note".into(), Field::string().optional()));
        item.fields.push(("level".into(), Field::number().default(1)));
        item.fields.push(("code".into(), Field::string().optional().unique()));
    }
    // Declared out of order on purpose: migrations must follow `order`.
    Schema { tables: vec![item, owner] }
}

/// A random lowercase suffix so repeated runs against a shared database don't collide.
pub fn random_suffix() -> String {
    crate::crypto::random_string(8, b"abcdefghijklmnopqrstuvwxyz0123456789")
}

fn rec(v: Value) -> Record {
    match v {
        Value::Object(m) => m,
        _ => panic!("expected an object"),
    }
}

fn get<'a>(r: &'a Record, k: &str) -> &'a Value {
    r.get(k).unwrap_or(&Value::Null)
}

fn names(rows: &[Record]) -> Vec<String> {
    let mut n: Vec<String> = rows.iter().map(|r| get(r, "name").as_str().unwrap_or_default().to_owned()).collect();
    n.sort();
    n
}

fn ordered(rows: &[Record]) -> Vec<&str> {
    rows.iter().map(|r| get(r, "name").as_str().unwrap_or_default()).collect()
}

fn w(field: &str, op: Operator, value: Value) -> Where {
    Where::new(field, op, value)
}

async fn find(db: &Db, where_: Vec<Where>) -> Vec<String> {
    names(&db.find_many("item", FindManyQuery { where_, ..Default::default() }).await.expect("find_many"))
}

fn query(sort: &str, dir: SortDirection, limit: Option<usize>, offset: Option<usize>) -> FindManyQuery {
    FindManyQuery { where_: vec![], limit, offset, sort_by: Some(SortBy { field: sort.into(), direction: dir }) }
}

/// Run the whole suite against `adapter`.
pub async fn run_adapter_suite(adapter: Arc<dyn Adapter>) {
    let suffix = random_suffix();
    let db = Db::new(adapter.clone(), Arc::new(suite_schema(&suffix, false)), IdGenerator::Random);
    db.migrate().await.expect("migrate");
    db.migrate().await.expect("migrate is idempotent");

    round_trips(&db).await;
    seed(&db).await;
    operators(&db).await;
    sorting_and_pagination(&db).await;
    unique_constraints(&db).await;
    writes(&db).await;
    consume_one(&db).await;
    transactions(&db).await;

    let db = Db::new(adapter, Arc::new(suite_schema(&suffix, true)), IdGenerator::Random);
    db.migrate().await.expect("migrate with a new column");
    db.migrate().await.expect("migrate with a new column is idempotent");
    added_columns(&db).await;
}

async fn round_trips(db: &Db) {
    let created = db
        .create(
            "item",
            rec(json!({
                "name": "roundtrip",
                "email": "roundtrip@example.com",
                "age": 7,
                "score": 9_007_199_254_740_993i64,
                "active": true,
                "expiresAt": "2024-01-01T01:30:00.123+01:00",
                "meta": { "a": 1, "b": [true, null], "c": "x" },
                "tags": ["x", "y"],
                "nums": [1, 2.5],
                "nickname": "rt",
            })),
            false,
        )
        .await
        .expect("create");
    let id = get(&created, "id").clone();
    assert!(id.as_str().is_some_and(|s| !s.is_empty()), "create returns an id: {created:?}");

    let found = db.find_one("item", &[Where::eq("id", id.clone())]).await.expect("find_one").expect("row exists");
    for row in [&created, &found] {
        assert_eq!(get(row, "name"), "roundtrip");
        assert_eq!(get(row, "age"), 7);
        assert_eq!(get(row, "score"), 9_007_199_254_740_993i64);
        assert_eq!(get(row, "active"), true);
        assert_eq!(get(row, "expiresAt"), "2024-01-01T00:30:00.123Z");
        assert_eq!(get(row, "meta"), &json!({ "c": "x", "a": 1, "b": [true, null] }));
        assert_eq!(get(row, "tags"), &json!(["x", "y"]));
        assert_eq!(get(row, "nums"), &json!([1, 2.5]));
        assert_eq!(get(row, "nickname"), "rt");
        let created_at = get(row, "createdAt").as_str().expect("createdAt default is a date string");
        assert!(crate::utils::date::parse_value(&json!(created_at)).is_some(), "{created_at}");
        assert!(created_at.ends_with('Z') && created_at.len() == 24, "{created_at}");
    }

    let defaults = db
        .create("item", rec(json!({ "name": "defaults", "email": "defaults@example.com", "age": 0 })), false)
        .await
        .expect("create with defaults");
    assert_eq!(get(&defaults, "active"), false);
    assert_eq!(get(&defaults, "nickname"), &Value::Null);
    assert_eq!(get(&defaults, "meta"), &Value::Null);

    let by_nick = db.find_one("item", &[Where::eq("nickname", "rt")]).await.expect("find by renamed column");
    assert_eq!(by_nick.map(|r| get(&r, "id").clone()), Some(id.clone()));

    let forced = db
        .create(
            "item",
            rec(json!({ "id": "forced-id", "name": "forced", "email": "forced@example.com", "age": 0 })),
            true,
        )
        .await
        .expect("create with forced id");
    assert_eq!(get(&forced, "id"), "forced-id");

    let updated = db
        .update("item", &[Where::eq("id", id.clone())], rec(json!({ "active": false, "expiresAt": 0, "meta": null })))
        .await
        .expect("update")
        .expect("updated row");
    assert_eq!(get(&updated, "active"), false);
    assert_eq!(get(&updated, "expiresAt"), "1970-01-01T00:00:00.000Z");
    assert_eq!(get(&updated, "meta"), &Value::Null);

    let none = db.find_one("item", &[Where::eq("name", "missing")]).await.expect("find_one");
    assert!(none.is_none());

    let n = db.delete_many("item", &[]).await.expect("delete_many all");
    assert_eq!(n, 3);
    assert_eq!(db.count("item", &[]).await.expect("count"), 0);
}

async fn seed(db: &Db) {
    let rows = [
        json!({ "name": "alpha", "email": "Alpha@Example.com", "age": 10, "active": true,
                "expiresAt": "2024-01-01T00:00:00.000Z", "tags": ["a", "b"], "nums": [1, 2] }),
        json!({ "name": "beta", "email": "beta@example.com", "age": 20, "active": false,
                "expiresAt": "2024-06-01T00:00:00.000Z", "tags": ["b"], "nums": [10] }),
        json!({ "name": "gamma", "email": "gamma@test.org", "age": 30, "active": true,
                "expiresAt": "2025-01-01T00:00:00.000Z", "nickname": "G" }),
        json!({ "name": "100%_[off]*?", "email": "promo@example.com", "age": 40, "active": false }),
        json!({ "name": "Delta", "email": "delta@TEST.org", "age": 50, "active": true, "nickname": "d" }),
    ];
    for r in rows {
        db.create("item", rec(r), false).await.expect("seed");
    }
}

const PROMO: &str = "100%_[off]*?";

async fn operators(db: &Db) {
    use Operator::*;
    let all = || {
        let mut v = vec!["alpha", "beta", "gamma", PROMO, "Delta"];
        v.sort();
        v
    };
    let s = |v: &[&str]| {
        let mut v: Vec<String> = v.iter().map(|s| s.to_string()).collect();
        v.sort();
        v
    };

    assert_eq!(find(db, vec![]).await, all());
    assert_eq!(find(db, vec![Where::eq("name", "beta")]).await, s(&["beta"]));
    assert_eq!(find(db, vec![Where::eq("email", "alpha@example.com")]).await, s(&[]));
    assert_eq!(find(db, vec![Where::eq("email", "alpha@example.com").insensitive()]).await, s(&["alpha"]));
    assert_eq!(find(db, vec![Where::eq("nickname", Value::Null)]).await, s(&["alpha", "beta", PROMO]));
    assert_eq!(find(db, vec![Where::ne("nickname", Value::Null)]).await, s(&["gamma", "Delta"]));
    assert_eq!(find(db, vec![Where::ne("name", "beta")]).await, s(&["alpha", "gamma", PROMO, "Delta"]));
    assert_eq!(
        find(db, vec![Where::ne("nickname", "G")]).await,
        s(&["alpha", "beta", PROMO, "Delta"]),
        "ne keeps NULLs"
    );
    assert_eq!(find(db, vec![Where::ne("nickname", "g").insensitive()]).await, s(&["alpha", "beta", PROMO, "Delta"]));

    assert_eq!(find(db, vec![w("age", Lt, json!(30))]).await, s(&["alpha", "beta"]));
    assert_eq!(find(db, vec![w("age", Lte, json!(30))]).await, s(&["alpha", "beta", "gamma"]));
    assert_eq!(find(db, vec![w("age", Gt, json!(30))]).await, s(&[PROMO, "Delta"]));
    assert_eq!(find(db, vec![w("age", Gte, json!(30))]).await, s(&["gamma", PROMO, "Delta"]));
    assert_eq!(find(db, vec![w("age", Eq, json!(20))]).await, s(&["beta"]));

    assert_eq!(find(db, vec![w("expiresAt", Gt, json!("2024-03-01T00:00:00.000Z"))]).await, s(&["beta", "gamma"]));
    assert_eq!(find(db, vec![w("expiresAt", Lte, json!("2024-06-01T02:00:00+02:00"))]).await, s(&["alpha", "beta"]));
    assert_eq!(find(db, vec![Where::eq("expiresAt", "2024-01-01T00:00:00Z")]).await, s(&["alpha"]));

    assert_eq!(find(db, vec![Where::eq("active", true)]).await, s(&["alpha", "gamma", "Delta"]));
    assert_eq!(find(db, vec![Where::eq("active", false)]).await, s(&["beta", PROMO]));

    assert_eq!(
        find(db, vec![Where::is_in("name", vec!["alpha".into(), "gamma".into(), "nope".into()])]).await,
        s(&["alpha", "gamma"])
    );
    assert_eq!(find(db, vec![Where::is_in("name", vec![])]).await, s(&[]));
    assert_eq!(find(db, vec![Where::is_in("age", vec![json!(10), json!(50)])]).await, s(&["alpha", "Delta"]));
    assert_eq!(
        find(db, vec![Where::is_in("email", vec!["ALPHA@example.com".into(), "DELTA@test.org".into()]).insensitive()])
            .await,
        s(&["alpha", "Delta"])
    );
    assert_eq!(
        find(db, vec![Where::is_in("nickname", vec![Value::Null, "G".into()])]).await,
        s(&["alpha", "beta", "gamma", PROMO])
    );
    assert_eq!(find(db, vec![w("name", NotIn, json!(["alpha", "gamma"]))]).await, s(&["beta", PROMO, "Delta"]));
    assert_eq!(find(db, vec![w("name", NotIn, json!([]))]).await, all());
    assert_eq!(find(db, vec![w("nickname", NotIn, json!(["G"]))]).await, s(&["alpha", "beta", PROMO, "Delta"]));
    assert_eq!(find(db, vec![w("nickname", NotIn, json!(["G", null]))]).await, s(&["Delta"]));

    assert_eq!(find(db, vec![w("name", Contains, json!("et"))]).await, s(&["beta"]));
    assert_eq!(find(db, vec![w("name", Contains, json!("%"))]).await, s(&[PROMO]));
    assert_eq!(find(db, vec![w("name", Contains, json!("_"))]).await, s(&[PROMO]));
    assert_eq!(find(db, vec![w("name", Contains, json!("%_[o"))]).await, s(&[PROMO]));
    assert_eq!(find(db, vec![w("name", Contains, json!("]*?"))]).await, s(&[PROMO]));
    assert_eq!(find(db, vec![w("name", Contains, json!("*"))]).await, s(&[PROMO]));
    assert_eq!(find(db, vec![w("name", Contains, json!("ELT"))]).await, s(&[]));
    assert_eq!(find(db, vec![w("name", Contains, json!("ELT")).insensitive()]).await, s(&["Delta"]));
    assert_eq!(
        find(db, vec![w("email", Contains, json!("EXAMPLE")).insensitive()]).await,
        s(&["alpha", "beta", PROMO])
    );
    assert_eq!(find(db, vec![w("name", StartsWith, json!("ga"))]).await, s(&["gamma"]));
    assert_eq!(find(db, vec![w("name", StartsWith, json!("d"))]).await, s(&[]));
    assert_eq!(find(db, vec![w("name", StartsWith, json!("d")).insensitive()]).await, s(&["Delta"]));
    assert_eq!(find(db, vec![w("name", StartsWith, json!(".*"))]).await, s(&[]));
    assert_eq!(find(db, vec![w("name", StartsWith, json!("100%"))]).await, s(&[PROMO]));
    assert_eq!(find(db, vec![w("name", EndsWith, json!("ta"))]).await, s(&["beta", "Delta"]));
    assert_eq!(find(db, vec![w("name", EndsWith, json!("*?"))]).await, s(&[PROMO]));
    assert_eq!(find(db, vec![w("email", EndsWith, json!("test.org"))]).await, s(&["gamma"]));
    assert_eq!(find(db, vec![w("email", EndsWith, json!("test.org")).insensitive()]).await, s(&["gamma", "Delta"]));

    assert_eq!(find(db, vec![w("tags", Contains, json!("b"))]).await, s(&["alpha", "beta"]));
    assert_eq!(find(db, vec![w("tags", Contains, json!("a"))]).await, s(&["alpha"]));
    assert_eq!(find(db, vec![w("nums", Contains, json!(1))]).await, s(&["alpha"]));

    assert_eq!(
        find(db, vec![w("age", Lt, json!(15)).or(), w("age", Gt, json!(45)).or()]).await,
        s(&["alpha", "Delta"])
    );
    assert_eq!(
        find(db, vec![Where::eq("active", true), Where::eq("name", "alpha").or(), Where::eq("name", "gamma").or()])
            .await,
        s(&["alpha", "gamma"])
    );
    assert_eq!(find(db, vec![Where::eq("active", true), w("age", Gt, json!(15))]).await, s(&["gamma", "Delta"]));
    assert_eq!(
        find(db, vec![Where::eq("name", "beta").or(), Where::eq("active", true), Where::eq("name", "Delta").or()])
            .await,
        s(&["Delta"]),
        "AND clauses bind regardless of position"
    );

    assert_eq!(db.count("item", &[]).await.expect("count"), 5);
    assert_eq!(db.count("item", &[Where::eq("active", true)]).await.expect("count"), 3);
    assert_eq!(db.count("item", &[Where::eq("name", "nope")]).await.expect("count"), 0);

    let one = db.find_one("item", &[w("age", Gte, json!(50))]).await.expect("find_one").expect("row");
    assert_eq!(get(&one, "name"), "Delta");
}

async fn sorting_and_pagination(db: &Db) {
    use SortDirection::*;
    let run = |q: FindManyQuery| async move { db.find_many("item", q).await.expect("find_many") };
    let asc = run(query("age", Asc, None, None)).await;
    assert_eq!(ordered(&asc), ["alpha", "beta", "gamma", PROMO, "Delta"]);
    let desc = run(query("age", Desc, None, None)).await;
    assert_eq!(ordered(&desc), ["Delta", PROMO, "gamma", "beta", "alpha"]);
    assert_eq!(ordered(&run(query("age", Asc, Some(2), None)).await), ["alpha", "beta"]);
    assert_eq!(ordered(&run(query("age", Asc, Some(2), Some(1))).await), ["beta", "gamma"]);
    assert_eq!(ordered(&run(query("age", Asc, None, Some(3))).await), [PROMO, "Delta"]);
    assert_eq!(ordered(&run(query("age", Desc, Some(10), Some(4))).await), ["alpha"]);
    assert!(run(query("age", Asc, None, Some(10))).await.is_empty());
    assert_eq!(ordered(&run(query("expiresAt", Desc, Some(2), None)).await), ["gamma", "beta"]);
    let nulls_first = run(query("expiresAt", Asc, Some(2), None)).await;
    assert_eq!(names(&nulls_first), [PROMO, "Delta"], "NULLs sort first ascending");
    assert_eq!(ordered(&run(query("email", Asc, Some(1), Some(1))).await), ["beta"]);

    let mut q = query("age", Desc, Some(1), Some(1));
    q.where_ = vec![Where::eq("active", true)];
    assert_eq!(ordered(&run(q).await), ["gamma"]);

    let limited = run(FindManyQuery { limit: Some(3), ..Default::default() }).await;
    assert_eq!(limited.len(), 3);
}

async fn unique_constraints(db: &Db) {
    let dup = db.create("item", rec(json!({ "name": "dup", "email": "beta@example.com", "age": 1 })), false).await;
    assert!(dup.is_err(), "duplicate unique value must fail");
    let dup = db.update("item", &[Where::eq("name", "alpha")], rec(json!({ "email": "beta@example.com" }))).await;
    assert!(dup.is_err(), "updating to a duplicate unique value must fail");
    assert_eq!(db.count("item", &[]).await.expect("count"), 5);
    let alpha = db.find_one("item", &[Where::eq("name", "alpha")]).await.expect("find").expect("alpha");
    assert_eq!(get(&alpha, "email"), "Alpha@Example.com");
}

async fn writes(db: &Db) {
    let updated = db
        .update("item", &[Where::eq("name", "beta")], rec(json!({ "name": "beta2", "age": 21 })))
        .await
        .expect("update")
        .expect("updated row");
    assert_eq!(get(&updated, "name"), "beta2");
    assert_eq!(get(&updated, "age"), 21);
    assert_eq!(get(&updated, "email"), "beta@example.com");
    assert_eq!(get(&updated, "tags"), &json!(["b"]));

    let missing = db.update("item", &[Where::eq("name", "nope")], rec(json!({ "age": 1 }))).await.expect("update");
    assert!(missing.is_none());

    let one = db
        .update("item", &[Where::eq("active", true)], rec(json!({ "nickname": "first" })))
        .await
        .expect("update")
        .expect("row");
    assert_eq!(get(&one, "nickname"), "first");
    assert_eq!(db.count("item", &[Where::eq("nickname", "first")]).await.expect("count"), 1, "update touches one row");

    let n =
        db.update_many("item", &[Where::eq("active", false)], rec(json!({ "age": 99 }))).await.expect("update_many");
    assert_eq!(n, 2);
    assert_eq!(find(db, vec![Where::eq("age", 99)]).await, ["100%_[off]*?", "beta2"]);
    let n = db.update_many("item", &[Where::eq("name", "nope")], rec(json!({ "age": 1 }))).await.expect("update_many");
    assert_eq!(n, 0);

    db.delete("item", &[Where::eq("name", "gamma")]).await.expect("delete");
    assert_eq!(db.count("item", &[]).await.expect("count"), 4);
    db.delete("item", &[Where::eq("name", "gamma")]).await.expect("deleting a missing row is not an error");
    db.delete("item", &[Where::eq("age", 99)]).await.expect("delete by non-unique field");
    assert_eq!(db.count("item", &[Where::eq("age", 99)]).await.expect("count"), 1, "delete removes one row");

    let n = db.delete_many("item", &[Where::eq("active", true)]).await.expect("delete_many");
    assert_eq!(n, 2);
    assert_eq!(db.count("item", &[]).await.expect("count"), 1);
    assert_eq!(db.delete_many("item", &[Where::eq("name", "nope")]).await.expect("delete_many"), 0);
}

async fn consume_one(db: &Db) {
    db.create("item", rec(json!({ "name": "token", "email": "token@example.com", "age": 1 })), false)
        .await
        .expect("create");
    let first = db.consume_one("item", &[Where::eq("email", "token@example.com")]).await.expect("consume_one");
    assert_eq!(first.as_ref().map(|r| get(r, "name").clone()), Some(json!("token")));
    let second = db.consume_one("item", &[Where::eq("email", "token@example.com")]).await.expect("consume_one");
    assert!(second.is_none());

    db.create("item", rec(json!({ "name": "race", "email": "race@example.com", "age": 1 })), false)
        .await
        .expect("create");
    let race = [Where::eq("email", "race@example.com")];
    let attempts = (0..8).map(|_| db.consume_one("item", &race));
    let results = futures::future::join_all(attempts).await;
    let won = results.into_iter().map(|r| r.expect("consume_one")).filter(Option::is_some).count();
    assert_eq!(won, 1, "exactly one concurrent consumer wins");
    assert_eq!(db.count("item", &[Where::eq("email", "race@example.com")]).await.expect("count"), 0);
}

async fn transactions(db: &Db) {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::{after_commit, in_transaction};
    use crate::error::Error;

    let item = |name: &str| rec(json!({ "name": name, "email": format!("{name}@example.com"), "age": 1 }));
    let by_name = |name: &str| vec![Where::eq("name", name)];
    let committed_hook = Arc::new(AtomicBool::new(false));
    let mut supported = false;

    db.transaction(async {
        supported = in_transaction();
        db.create("item", item("tx1"), false).await?;
        assert!(db.find_one("item", &by_name("tx1")).await?.is_some(), "reads see the transaction's writes");
        // A nested transaction joins the outer one.
        db.transaction(async { db.update("item", &by_name("tx1"), rec(json!({ "age": 2 }))).await }).await?;
        let flag = committed_hook.clone();
        after_commit(Box::pin(async move {
            flag.store(true, Ordering::SeqCst);
            Ok(())
        }))
        .await?;
        if supported {
            assert!(!committed_hook.load(Ordering::SeqCst), "after-commit work waits for the commit");
        }
        Ok::<_, Error>(())
    })
    .await
    .expect("transaction commits");
    let tx1 = db.find_one("item", &by_name("tx1")).await.expect("find").expect("committed row");
    assert_eq!(get(&tx1, "age"), 2);
    assert!(committed_hook.load(Ordering::SeqCst), "after-commit work runs");

    if supported {
        let rolled_back_hook = Arc::new(AtomicBool::new(false));
        let result = db
            .transaction(async {
                db.create("item", item("tx2"), false).await?;
                db.update("item", &by_name("tx1"), rec(json!({ "age": 3 }))).await?;
                db.delete_many("item", &by_name("a")).await?;
                let flag = rolled_back_hook.clone();
                after_commit(Box::pin(async move {
                    flag.store(true, Ordering::SeqCst);
                    Ok(())
                }))
                .await?;
                Err::<(), _>(Error::Database("boom".into()))
            })
            .await;
        assert!(result.is_err());
        assert!(db.find_one("item", &by_name("tx2")).await.expect("find").is_none(), "rolled-back insert is gone");
        let tx1 = db.find_one("item", &by_name("tx1")).await.expect("find").expect("row");
        assert_eq!(get(&tx1, "age"), 2, "rolled-back update is undone");
        assert!(!rolled_back_hook.load(Ordering::SeqCst), "after-commit work is dropped on rollback");

        // A failed statement inside the transaction rolls back earlier writes too.
        let result = db
            .transaction(async {
                db.create("item", item("tx3"), false).await?;
                db.create("item", item("tx1"), false).await?; // duplicate unique email
                Ok::<_, Error>(())
            })
            .await;
        assert!(result.is_err(), "unique violation fails the transaction");
        assert!(db.find_one("item", &by_name("tx3")).await.expect("find").is_none());
    }

    db.delete_many("item", &by_name("tx1")).await.expect("cleanup");
}

async fn added_columns(db: &Db) {
    let before = db.find_many("item", FindManyQuery::default()).await.expect("existing rows still readable");
    assert_eq!(before.len(), 1);
    let created = db
        .create("item", rec(json!({ "name": "noted", "email": "noted@example.com", "age": 3, "note": "hello" })), false)
        .await
        .expect("create with new columns");
    assert_eq!(get(&created, "note"), "hello");
    assert_eq!(get(&created, "level"), 1);
    let found = db.find_one("item", &[Where::eq("note", "hello")]).await.expect("find").expect("row");
    assert_eq!(get(&found, "name"), "noted");
    let updated = db
        .update("item", &[Where::eq("name", "noted")], rec(json!({ "level": 5 })))
        .await
        .expect("update")
        .expect("row");
    assert_eq!(get(&updated, "level"), 5);

    let coded = rec(json!({ "name": "c1", "email": "c1@example.com", "age": 1, "code": "c" }));
    db.create("item", coded, false).await.expect("create with unique code");
    let dup = rec(json!({ "name": "c2", "email": "c2@example.com", "age": 1, "code": "c" }));
    assert!(db.create("item", dup, false).await.is_err(), "an added unique column is enforced");
}
