pub fn export_matches(export_path: &[u8], request_path: &[u8]) -> bool {
    request_path == export_path
        || (export_path == b"/" && request_path.starts_with(b"/"))
        || (request_path.starts_with(export_path) && request_path.get(export_path.len()) == Some(&b'/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_matching_uses_component_boundaries() {
        assert!(export_matches(b"/data", b"/data"));
        assert!(export_matches(b"/data", b"/data/subdir"));
        assert!(!export_matches(b"/data", b"/database"));
        assert!(export_matches(b"/", b"/anything"));
        assert!(export_matches(b"/", b"/"));
        assert!(export_matches(b"/data", b"/data/"));
        assert!(!export_matches(b"/", b""));
        assert!(!export_matches(b"/", b"relative"));
        assert!(!export_matches(b"/data", b"/dat"));
        assert!(!export_matches(b"/data", b"data"));
        assert!(!export_matches(b"/data/sub", b"/data"));
    }
}
