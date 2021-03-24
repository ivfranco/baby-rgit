# baby-rgit

A Rust clone of the very first commit of git.

# Changes

- SHA256 instead of SHA1.
- A lot of the entries in the original `cache_entry` will be missing, device number / uid / gid /
  inode as a concept doesn't exist on a few platforms supported by stable Rust, hopefully the extra
  robustness of SHA256 over SHA1 would be sufficient for the purpose.
- Environmental variable controls the location of everything, not only the object store.

# Plans

- Safe Rust as much as possible.

# Progress

- [ ] Methods of directory cache:
  - [x] read_cache
  - [x] write_cache
  - [x] read_sha1_file
  - [x] write_sha1_file
  - [ ] check_valid_sha1
- [ ] Binaries
  - [ ] init-db
  - [ ] write-tree
  - [ ] read-tree
  - [ ] update-cache
  - [ ] commit-tree
  - [ ] show-diff
  - [ ] cat-file
- [ ] Sufficient tests for all of them
