exec >&2
find . -name '*~' | xargs rm -f
rm -rf *.app *.zip *.tar.gz
rm -f bits/runpython *.nib sources.list
