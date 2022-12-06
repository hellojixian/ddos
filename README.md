
## Compliation
complie with gcc
````
make
````

## Usage
syntax: ./flood [[-t IP] [-p PORT] [-r]

options:
	-t the target: IP (default 127.0.0.1)
	-p the target: PORT (default 80)
	-r set RST flag

	Example: sudo ./flood -t 192.168.0.1 -p 8080"

## Reference
For checking target IP address
````
nslookup www.gov.cn
````

For monitoring outgoing packets on Mac
````
sudo tcpdump -n host 156.251.67.7 and port 80
````

For monitoring traffic
````
brew install nload
nload -n en0
````