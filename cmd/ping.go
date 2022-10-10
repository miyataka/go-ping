package main

import (
	"fmt"
	"os"

	"github.com/miyataka/go-ping"
)

func main() {
	args := os.Args[1:]
	if len(args) != 1 {
		fmt.Println("go-ping command accepts only single argument. That's remote IPv4 address.")
		os.Exit(1)
	}

	ping.DoPing(args[0])
}
