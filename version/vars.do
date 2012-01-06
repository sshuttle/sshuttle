redo-ifchange gitvars prodname

read PROD <prodname

exec <gitvars
read COMMIT
read NAMES
read DATE

# the list of names is of the form:
#   (x,y,tag: $PROD-####,tag: $PROD-####,a,b)
# The entries we want are the ones starting with "tag: $PROD-" since those
# refer to the right actual git tags.
names_to_tag()
{
	x=${1#\(}
	x=${x%\)}
	cur=
	while [ "$cur" != "$x" ]; do
		x=${x# }
		x=${x#tag: }
		cur=${x%%,*}
		tagpost=${cur#$PROD-}
		if [ "$cur" != "$tagpost" ]; then
			echo "$tagpost"
			return 0
		fi
		x=${x#*,}
	done
	commitpost=${COMMIT#???????}
	commitpre=${COMMIT%$commitpost}
	echo "unknown-$commitpre"
}


sTAG=$(names_to_tag "$NAMES")

echo "COMMIT='$COMMIT'"
echo "TAG='$sTAG'"
echo "DATE='${DATE%% *}'"
