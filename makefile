

all: flood.c
	@gcc -Wno-format-overflow -g flood.c -o flood

	@echo "Done\\nExample: sudo ./flood -t 192.168.0.1 -p 8080"

clean:
	rm flood
	    @echo Clean done
