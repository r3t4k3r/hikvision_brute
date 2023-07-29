# hikvision_brute
Brute Hikvision CAMS with CVE-2021-36260 Exploit

# run
`go run src/main.go -help` to get help with running args

# run example
`go run src/main.go -infile ../CVE-NEW/hikvision_list.txt.bak -threads 300 -max_tries 3 -timeout 10 -delay 2000 -good good_out.txt -bad bad_out.txt -err err_out.txt -unknown unknown_out.txt`

# attention
software have some memory leaks, i don't know where is it in code
