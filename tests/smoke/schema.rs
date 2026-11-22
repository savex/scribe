//! Each backend has one migration and one snapshot per schema version.

use scribe_storage_api::SCHEMA_VERSION;
use scribe_tests::testdata;

#[test]
fn sqlite_has_one_migration_per_schema_version() {
    let migrations = scribe_storage_sqlite::MIGRATIONS;
    assert_eq!(migrations.len(), SCHEMA_VERSION as usize);
    assert!(migrations.iter().all(|sql| !sql.trim().is_empty()));
}

#[test]
fn postgres_has_one_migration_per_schema_version() {
    let migrations = scribe_storage_postgres::MIGRATIONS;
    assert_eq!(migrations.len(), SCHEMA_VERSION as usize);
    assert!(migrations.iter().all(|sql| !sql.trim().is_empty()));
}

#[test]
fn every_schema_version_has_a_sqlite_snapshot() {
    for v in 1..=SCHEMA_VERSION {
        let path = testdata(&format!("db/sqlite/v{v}.db"));
        assert!(
            path.is_file(),
            "missing {}; run testdata/db/build.sh",
            path.display()
        );
    }
}

#[test]
fn every_schema_version_has_a_postgres_seed() {
    for v in 1..=SCHEMA_VERSION {
        let path = testdata(&format!("db/postgres/v{v}_seed.sql"));
        assert!(
            path.is_file(),
            "missing {}; run testdata/db/build.sh",
            path.display()
        );
    }
}
