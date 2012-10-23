exec >&2
if pandoc </dev/null 2>/dev/null; then
	pandoc -s -r markdown -w man -o $3 $1.md
else
	echo "Warning: pandoc not installed; can't generate manpages."
	redo-always
fi
