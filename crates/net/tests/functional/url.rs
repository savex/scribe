use scribe_net::{checked_url, NetError};

#[test]
fn https_anywhere_http_only_to_loopback() {
    let t = checked_url("https://hooks.example.com/alerts?token=x").unwrap();
    assert!(t.tls);
    assert_eq!((t.host.as_str(), t.port), ("hooks.example.com", 443));
    assert_eq!(t.path_query, "/alerts?token=x");
    assert_eq!(
        t.to_string(),
        "https://hooks.example.com/alerts",
        "query never shown"
    );

    for ok in [
        "http://127.0.0.1:8080/x",
        "http://localhost/x",
        "http://[::1]:9/",
        "http://127.10.0.1/",
    ] {
        let t = checked_url(ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
        assert!(!t.tls);
    }
    assert_eq!(
        checked_url("http://[::1]:9/").unwrap().host_header(),
        "[::1]:9"
    );
    assert_eq!(checked_url("https://example.net").unwrap().path_query, "/");

    assert!(matches!(
        checked_url("http://hooks.example.com/"),
        Err(NetError::NotHttps(_))
    ));
    assert!(matches!(
        checked_url("http://192.0.2.1/"),
        Err(NetError::NotHttps(_))
    ));
    for bad in [
        "ftp://example.com/x",
        "hooks.example.com/x",
        "https://user:pw@example.com/",
        "https:///x",
    ] {
        assert!(
            matches!(checked_url(bad), Err(NetError::Url(..))),
            "{bad} was accepted"
        );
    }
}

#[test]
fn redirect_targets_resolve_and_compare_by_origin() {
    let base = checked_url("https://example.com/a/b?x=1").unwrap();
    assert_eq!(base.join("/c").unwrap().path_query, "/c");
    assert_eq!(base.join("d?y=2").unwrap().path_query, "/a/d?y=2");
    let abs = base.join("https://example.com:443/e").unwrap();
    assert!(abs.same_origin(&base));
    assert!(!base
        .join("https://example.net/")
        .unwrap()
        .same_origin(&base));
    assert!(!base
        .join("https://example.com:8443/")
        .unwrap()
        .same_origin(&base));
    assert!(!base.join("//example.net/").unwrap().same_origin(&base));
    assert!(matches!(
        base.join("http://example.com/"),
        Err(NetError::NotHttps(_))
    ));
}
