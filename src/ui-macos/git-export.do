# update a local branch with pregenerated output files, so people can download
# the completed tarballs from github.  Since we don't have any real binaries,
# our final distribution package contains mostly blobs from the source code,
# so this doesn't cost us much extra space in the repo.
BRANCH=dist/macos
redo-ifchange 'Sshuttle VPN.app'
git update-ref refs/heads/$BRANCH origin/$BRANCH '' 2>/dev/null || true

export GIT_INDEX_FILE=$PWD/gitindex.tmp
rm -f "$GIT_INDEX_FILE"
git add -f 'Sshuttle VPN.app'

MSG="MacOS precompiled app package for $(git describe)"
TREE=$(git write-tree --prefix=ui-macos)
git show-ref refs/heads/$BRANCH >/dev/null && PARENT="-p refs/heads/$BRANCH"
COMMITID=$(echo "$MSG" | git commit-tree $TREE $PARENT)

git update-ref refs/heads/$BRANCH $COMMITID
rm -f "$GIT_INDEX_FILE"