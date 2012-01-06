/bin/ls *.md |
sed 's/\.md/.8/' |
xargs redo-ifchange

redo-always
