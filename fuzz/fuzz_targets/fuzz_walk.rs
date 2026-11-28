#![no_main]
//! Directory walks over arbitrary trees of directories, files, and links.
//!
//! The input describes a tree, one entry per line:
//!
//! ```text
//! dir <parent> <name>
//! file <parent> <name>
//! link <parent> <name> <target>
//! ```
//!
//! `<parent>` indexes the directories created so far (0 is the rules root),
//! and `<target>` is `node:<index>` (any entry created so far), `root`,
//! `outside` (a directory next to the root), `outside-file` (a rule file in
//! it), `fsroot` (`/`), or `missing`. The tree is built in a fresh temporary
//! directory and walked confined and, unless a link leads to `/`, following
//! external links. Invariants: both walks finish; each real file is returned
//! once; a confined walk returns only files under the root and never reads
//! the outside file, which holds a secret that must not reach any parser
//! diagnostic; a confined walk returns a subset of what a following walk
//! returns.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 4096 {
        return;
    }
    #[cfg(unix)]
    if let Ok(text) = std::str::from_utf8(data) {
        imp::run(text);
    }
});

#[cfg(unix)]
mod imp {
    use std::collections::HashSet;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use rsigma_parser::walk::{WalkOptions, walk_files};

    const SECRET: &str = "TOPSECRET-FUZZ-WALK";
    const MAX_ENTRIES: usize = 64;

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn name(raw: &str) -> Option<String> {
        let ok = !raw.is_empty()
            && raw.len() <= 24
            && raw != "."
            && raw != ".."
            && raw
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
        ok.then(|| raw.to_string())
    }

    struct Scratch(PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    pub fn run(text: &str) {
        let scratch = Scratch(std::env::temp_dir().join(format!(
            "rsigma-fuzz-walk-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        )));
        let root = scratch.0.join("rules");
        let outside = scratch.0.join("outside");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("secret.yml"), format!("title: [{SECRET}\n")).unwrap();

        let mut dirs: Vec<PathBuf> = vec![root.clone()];
        let mut nodes: Vec<PathBuf> = vec![root.clone()];
        let mut real_files = 0usize;
        let mut links_to_fsroot = false;

        for line in text.lines().take(MAX_ENTRIES) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            let (kind, parent, entry) = match parts.as_slice() {
                [kind, parent, entry, ..] => (*kind, *parent, *entry),
                _ => continue,
            };
            let Ok(parent) = parent.parse::<usize>() else {
                continue;
            };
            let Some(entry) = name(entry) else { continue };
            let path = dirs[parent % dirs.len()].join(entry);
            if fs::symlink_metadata(&path).is_ok() {
                continue;
            }
            match (kind, parts.get(3)) {
                ("dir", _) => {
                    if fs::create_dir(&path).is_ok() {
                        dirs.push(path.clone());
                        nodes.push(path);
                    }
                }
                ("file", _) => {
                    let title = path.file_name().unwrap().to_string_lossy().to_string();
                    let rule = format!(
                        "title: {title}\nlogsource:\n  product: test\ndetection:\n  sel:\n    a: b\n  condition: sel\n"
                    );
                    if fs::write(&path, rule).is_ok() {
                        real_files += 1;
                        nodes.push(path);
                    }
                }
                ("link", Some(target)) => {
                    let target: PathBuf = match *target {
                        "root" => root.clone(),
                        "outside" => outside.clone(),
                        "outside-file" => outside.join("secret.yml"),
                        "fsroot" => {
                            links_to_fsroot = true;
                            PathBuf::from("/")
                        }
                        "missing" => scratch.0.join("missing"),
                        other => match other
                            .strip_prefix("node:")
                            .and_then(|i| i.parse::<usize>().ok())
                        {
                            Some(i) => nodes[i % nodes.len()].clone(),
                            None => continue,
                        },
                    };
                    if std::os::unix::fs::symlink(&target, &path).is_ok() {
                        nodes.push(path);
                    }
                }
                _ => {}
            }
        }

        let real_root = fs::canonicalize(&root).unwrap();
        let confined = walk_files(&root, &WalkOptions::default()).unwrap();
        check_unique(&confined.files);
        for file in &confined.files {
            assert!(file.path.starts_with(&root), "{file:?}");
            assert!(file.real_path.starts_with(&real_root), "{file:?}");
            assert!(fs::metadata(&file.real_path).unwrap().is_file());
        }
        for skipped in &confined.skipped {
            assert!(skipped.path.starts_with(&root), "{skipped:?}");
            let message = skipped.to_string();
            assert!(!message.contains(&*outside.to_string_lossy()), "{message}");
        }
        assert!(confined.files.len() <= real_files, "{confined:?}");

        let collection = rsigma_parser::parse_sigma_directory(&root).unwrap();
        for diagnostic in &collection.diagnostics {
            assert!(!diagnostic.message.contains(SECRET), "{diagnostic:?}");
        }

        if !links_to_fsroot {
            let followed =
                walk_files(&root, &WalkOptions::new().follow_external_links(true)).unwrap();
            check_unique(&followed.files);
            assert!(followed.files.len() <= real_files + 1);
            let followed_real: HashSet<&Path> =
                followed.files.iter().map(|f| f.real_path.as_path()).collect();
            for file in &confined.files {
                assert!(followed_real.contains(file.real_path.as_path()), "{file:?}");
            }
        }
    }

    fn check_unique(files: &[rsigma_parser::walk::WalkedFile]) {
        let mut seen = HashSet::new();
        for file in files {
            assert!(seen.insert(&file.real_path), "{:?} returned twice", file.real_path);
        }
    }
}
