# baby-rgit

A Rust clone of the ~~very first commit of git~~ the first commit cannot unpack directories from
object files, the first functioning commit is the third one.

# Changes

- SHA256 instead of SHA1.
- A lot of the entries in the original `cache_entry` will be missing, device number / uid / gid /
  inode as a concept doesn't exist on a few platforms supported by stable Rust, hopefully the extra
  robustness of SHA256 over SHA1 would be sufficient for the purpose.
- Environmental variable controls the location of everything, not only the object store.

# Plans

- Safe Rust as much as possible.

# Progress

- [x] Methods of directory cache:
  - [x] init
  - [x] read_cache
  - [x] write_cache
  - [x] read_sha1_file
  - [x] write_sha1_file
  - [x] check_valid_sha1
- [ ] Binaries
  - [x] init-db
  - [x] write-tree
  - [x] read-tree
  - [x] update-cache
  - [ ] commit-tree
  - [ ] show-diff
  - [ ] cat-file
- [ ] Sufficient tests for all of them
