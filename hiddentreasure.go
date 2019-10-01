/*
Copyright (c) 2019, AverageSecurityGuy
# All rights reserved.
*/

package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

func printLine(msg string) {
	fmt.Printf("[*] %s\n", msg)
}

func printGood(msg string) {
	fmt.Printf("[+] %s\n", msg)
}

func printError(msg string) {
	fmt.Printf("[E] %s\n", msg)
}

func open(fileName string) *os.File {
	file, err := os.Open(fileName)
	if err != nil {
		printError(err.Error())
	}

	return file
}

func checkHost(host string) []string {
	var hosts []string

	httpNoExist := fmt.Sprintf("http://%s/mbRPPgCdHHcqu6wYgMaC7Z0u", host)
	exist, _, err := getUrl(httpNoExist)

	// If there is an error or the page exists, I do not want to keep this host.
	if !((err != nil) || (exist)) {
		hosts = append(hosts, fmt.Sprintf("http://%s", host))
	}

	httpsNoExist := fmt.Sprintf("https://%s/mbRPPgCdHHcqu6wYgMaC7Z0u", host)
	exist, _, err = getUrl(httpsNoExist)

	if !((err != nil) || (exist)) {
		hosts = append(hosts, fmt.Sprintf("https://%s", host))
	}

	return hosts
}

func getHosts(hostChan chan string, hostFile string) {
	hosts := open(hostFile)
	hscan := bufio.NewScanner(hosts)

	for hscan.Scan() {
		host := hscan.Text()

		if strings.HasPrefix(host, "#") || host == "" {
			continue
		}

		hostChan <- host
	}

	close(hostChan)
}

func getWords(wordFile string) []string {
	var words []string

	file := open(wordFile)
	scan := bufio.NewScanner(file)

	for scan.Scan() {
		word := scan.Text()

		if strings.HasPrefix(word, "#") || word == "" {
			continue
		}

		words = append(words, word)
	}

	return words
}

func processHost(host string, endPoints, badWords []string) {
	for _, host := range checkHost(host) {
		for _, ep := range endPoints {
			url := fmt.Sprintf("%s/%s", host, ep)
			exist, body, _ := getUrl(url)

			// If the page exists and the body is not bad, I want it.
			if exist && !badBody(body, badWords) {
				printGood(url)
			}
		}
	}
}

func badBody(body string, badWords []string) bool {

	if body == "" {
		return true
	}

	for _, word := range badWords {
		if strings.Contains(body, word) {
			return true
		}
	}

	return false
}

func getUrl(url string) (bool, string, error) {
	var netClient = &http.Client{
		Timeout: time.Second * 5,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := netClient.Get(url)
	if err != nil {
		return false, "", err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)

	switch {
	case err != nil:
		return false, "", err
	case resp.StatusCode == 200:
		return true, string(body), nil
	default:
		return false, "", nil
	}
}

func main() {
	// handle arguments
	if len(os.Args) != 4 {
		fmt.Println("Usage: hiddentreasure host_file end_point_file bad_word_file")
		os.Exit(1)
	}

	var wg sync.WaitGroup

	hostFile := os.Args[1]
	wordFile := os.Args[2]
	badFile := os.Args[3]

	endPoints := getWords(wordFile)
	badWords := getWords(badFile)
	hostChan := make(chan string, 100)

	// Workers to check for good URLs
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(hosts chan string, endPoints []string) {
			defer wg.Done()

			for host := range hostChan {
				processHost(host, endPoints, badWords)
			}
		}(hostChan, endPoints)
	}

	// Build channel of valid hosts
	go getHosts(hostChan, hostFile)

	wg.Wait()
}
