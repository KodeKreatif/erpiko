1. Clone portable
2. Run `autogen.sh`
3. Patch with `cmp.patch` in this directory
4. Hack and build
5. Copy `crypto` and `include` somewhere else
6. `git reset` and `clean -xdf`
7. Run `autogen.sh` again
8. Move `crypto` and `include` as `cryptoold` and `includeold`
9. Copy back `crypto` and `include` from #5
10. `diff -Naur cryptoold crypto >> /tmp/cmp.patch` 
11. `diff -Naur includeold include >> /tmp/cmp.patch` 
12. Copy `/tmp/cmp.patch` to this directory
13. Party
