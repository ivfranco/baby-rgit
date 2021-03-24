# Changes

- SHA256 instead of SHA1.
- A lot of the entries in the original `cache_entry` will be missing, device number / uid / gid /
  inode as a concept doesn't exist on a few platforms supported by stable Rust, hopefully the extra
  robustness of SHA256 over SHA1 would be sufficient for the purpose.

# Plans

- Safe Rust as much as possible.
