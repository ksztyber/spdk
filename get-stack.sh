#!/usr/bin/env bash

set -e

app=build/examples/bdevperf
lineno=

get_stack() {
	local fname lineno out start end

	fname=$1 lineno=${2:-0}
	out=$(tail -n +$lineno $fname | awk -f <(cat <<- EOF
		BEGIN { prev = 0 }
		!/print_stack/ { exit 0 }
		\$(NF - 2) !~ "#" prev + 1 ":" { exit 0 }
		{
			print \$0
			prev++
		}
		EOF
		)
	)

	# Do sanity checks
	if [[ -z "$out" ]]; then
		echo "Backtrace doesn't start at the beginning:" >&2
		tail -n +$lineno $fname | head >&2
		return 1
	fi

	echo "$out"
}

print_stack() {
	local addr stack args=()

	stack=$(get_stack $1 $2)
	for addr in $(get_stack $1 $2 | awk '{print $NF}' $file | tr -d '[]'); do
		args+=(-ex "info symbol $addr")
	done

	gdb "${args[@]}" -ex quit "$app" | awk -f <(cat <<- EOF
		{ if (start) printf("%s %s %s\n", \$1, \$2, \$3); }
		/Reading symbols from/{ start=1 }
		EOF
	)
}

while getopts 'n:' optchar; do
	case "$optchar" in
		n) lineno="$OPTARG" ;;
		*) exit 1 ;;
	esac
done
shift $((OPTIND - 1))

print_stack $1 $lineno
