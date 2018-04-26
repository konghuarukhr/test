 1852  sudo iptables -tnat -APOSTROUTING -o enp0s3 -pudp --dport 53 -jDNAT --to-destination 8.8.4.4
 1854  sudo iptables -tnat -AOUTPUT -o enp0s3 -pudp --dport 53 -jDNAT --to-destination 8.8.4.4
 1947  sudo iptables -tnat -APREROUTING -i docker0 -pudp --dport 53 -jDNAT --to-destination 8.8.4.4
 1998  history | grep DNAT
 1999  history | grep DNAT > ../scripts/clientdns.sh
