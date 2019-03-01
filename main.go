package main

/* TODO: Instead of checking two levels. Add completed domains to a threadsafe queue, and read from there
If NoError && ! CNAME then add to queue

*/
import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/miekg/dns"
	"github.com/sheerun/queue"
	"golang.org/x/sync/semaphore"
)

var noThreads = 100

const noFlag = "MISSING_FLAG"

var stringDelims = []string{"", "0", "1", "2", "3", "-", "_"}
var ctx = context.Background()

var config, _ = dns.ClientConfigFromFile("/etc/resolv.conf")
var client = new(dns.Client)

func readFile(file string) string {
	b, err := ioutil.ReadFile(file)
	if err != nil {
		fmt.Println(err)
		panic("File not found")
	}

	return string(b)
}

func getTextRecord(domain string) string {
	txt, err := net.LookupTXT(domain)

	if err == nil {
		return strings.Join(txt, "\n")
	} else {
		return ""
	}
}

func noError(domain string) bool {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeCNAME)
	r, _, _ := client.Exchange(m, net.JoinHostPort(config.Servers[0], config.Port))
	if r == nil {
		return false
	}
	return strings.Contains(r.String(), "NOERROR")
}

// first check dns then http
func check(domain string, saveDirectory string) bool {
	cname, cnameErr := net.LookupCNAME(domain)
	ips, err := net.LookupIP(domain)
	if err == nil {
		resp, err := http.Get("http://" + domain)
		txt := getTextRecord(domain)

		if err == nil {
			defer resp.Body.Close()
			body, _ := ioutil.ReadAll(resp.Body)

			err := ioutil.WriteFile(filepath.Join(saveDirectory, domain), body, 0644)
			if err != nil {
				fmt.Println("Tried to write file but received err", err)
			}
			fmt.Println("Found:", resp.Status, ips, domain, "cname="+cname)
		} else {
			fmt.Println("DNS ONLY:", domain, err)
			err := ioutil.WriteFile(filepath.Join(saveDirectory, domain), []byte(err.Error()), 0644)
			if err != nil {
				fmt.Println("Tried to write file but received err", err)
			}
		}

		if txt != "" {
			err := ioutil.WriteFile(filepath.Join(saveDirectory, domain+"-txt"), []byte(txt), 0644)
			if err != nil {
				fmt.Println("Tried to write file but received err", err)
			}
		}
	}

	return (cnameErr == nil && cname == domain+".") || noError(domain)
}

func appendSubdomainToQueue(words *queue.Queue, subdomain string, originalWordlist []string) {
	fmt.Println("Searching deaper for subdomain", subdomain)
	for _, word := range originalWordlist {
		words.Append(word + "." + subdomain)
	}
}

// Checks if either queue is non empty,
// of all threads are not completed.
// Waits for all threads to be completed then tries again
func wordAvailable(words *queue.Queue, sem *semaphore.Weighted) bool {
	if words.Length() > 0 {
		return true
	}

	// Acquire 1 semaphore at a time, checking for length of queue each time
	i := 0
	for ; i < noThreads; i++ {
		sem.Acquire(ctx, 1)
		if words.Length() > 0 {
			sem.Release(int64(i + 1))
			return true
		}
	}
	sem.Release(int64(noThreads))
	return false
}

func runPermutations(words *queue.Queue, domain string, saveDirectory string, sem *semaphore.Weighted, originalWordlist []string) {
	for wordAvailable(words, sem) {
		word, _ := words.Pop().(string)

		subdomain := word + "." + domain
		if err := sem.Acquire(ctx, 1); err != nil {
			fmt.Println(err)
			panic("Semaphore error")
		}

		go func() {
			if check(subdomain, saveDirectory) {
				appendSubdomainToQueue(words, word, originalWordlist)
			}
			sem.Release(1)
		}()
	}

}

func generatePermutations(wordlist []string) []string {
	var perms []string
	for _, delim := range stringDelims {
		for _, word := range append([]string{""}, wordlist...) {
			// Prepend "" to the word list so that we test all subdomains on their own before trying any perms
			for _, subWord := range wordlist {
				perms = append(perms, subWord+delim+word)
			}
		}
	}
	return perms
}

func runSpammer(worldlistFile string, domain string, saveDirectory string) {
	wordlist := generatePermutations(strings.Split(readFile(worldlistFile), "\n"))
	fmt.Println("Generated", len(wordlist), "permutations")
	wordQueue := queue.New()
	for _, word := range wordlist {
		// Add all words to the queue in reverse order

		wordQueue.Append(word)
	}

	var sem = semaphore.NewWeighted(int64(noThreads))
	runPermutations(wordQueue, domain, saveDirectory, sem, wordlist)
	fmt.Println("Waiting for threads to finish up...")
	// Acquire all locks (all threads completed) before continuing
	sem.Acquire(ctx, int64(noThreads))
}

func main() {
	worldlistFile := flag.String("wordlist", noFlag, "Word list for spam")
	domain := flag.String("domain", noFlag, "Domain to attack")

	flag.Parse()

	if *worldlistFile == noFlag || *domain == noFlag {
		fmt.Println("Please enter all required flags")
	} else {
		saveDirectory := filepath.Join("/tmp", *domain)
		os.Mkdir(saveDirectory, os.ModePerm)
		fmt.Println("Max threads is", noThreads)

		runSpammer(*worldlistFile, *domain, saveDirectory)
		fmt.Println("Files saved to", saveDirectory)
	}
}
