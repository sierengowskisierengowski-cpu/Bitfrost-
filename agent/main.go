package main

import (
	"flag"
	"log"
)

func main() {
	mode := flag.String("mode", "both", "Run mode: collector, executor, or both")
	flag.Parse()

	log.Println("╔══════════════════════════════════════════╗")
	log.Println("║        BIFROST GO AGENT v0.1.0           ║")
	log.Println("║        The Bridge Is Watched             ║")
	log.Println("╚══════════════════════════════════════════╝")

	switch *mode {
	case "collector":
		startCollector()
	case "executor":
		startExecutor()
	case "both":
		go startCollector()
		startExecutor()
	default:
		log.Fatalf("[!] Unknown mode: %s", *mode)
	}
}
