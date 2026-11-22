//! Migrations and schema snapshots stay in step with the storage API's schema version.

use std::path::Path;

use scribe_storage_api::SCHEMA_VERSION;
use scribe_storage_postgres::MIGRATIONS;

mod smoke {
    use super::*;

    #[test]
    fn one_migration_per_schema_version() {
        assert_eq!(MIGRATIONS.len(), SCHEMA_VERSION as usize);
        assert!(MIGRATIONS.iter().all(|sql| !sql.trim().is_empty()));
    }

    #[test]
    fn every_schema_version_has_a_snapshot() {
        let db = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/db");
        for v in 1..=SCHEMA_VERSION {
            let path = db.join(format!("postgres/v{v}_seed.sql"));
            assert!(
                path.is_file(),
                "missing snapshot {}; run testdata/db/build.sh",
                path.display()
            );
        }
    }
}
