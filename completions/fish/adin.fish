# Fish completions for ADIN (Automated Cryptographic Inspector).
complete -c adin -f
complete -c adin -s h -l help -d 'Show help and exit'
complete -c adin -l version -d 'Show version information'
complete -c adin -s f -l file -r -F -d 'Read bytes from a file'
complete -c adin -l json -d 'Print a machine-readable JSON report'
complete -c adin -l verbose -d 'Show all candidates and technical parameters'
complete -c adin -l depth -r -a '0 1 2 3 4 5 6 7 8 9 10' -d 'Maximum nested decode depth'
complete -c adin -l max-bytes -r -a '1024 4096 65536 1048576 4194304' -d 'Maximum input size in bytes'
