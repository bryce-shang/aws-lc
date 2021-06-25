package main

import (
	// 	"bufio"
	"bytes"
	// 	"encoding/base64"
	// 	"encoding/binary"
	// 	"compress/bzip2"

	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"boringssl.googlesource.com/boringssl/atsec/common"
	"boringssl.googlesource.com/boringssl/atsec/subprocess"
)

var (
	// 	inputFileDirectory       = flag.String("in", "/Users/shanggu/Desktop/tv2", "Directory of a vector-set input files.")
	// 	inputFileDirectory  = flag.String("in", "/Users/shanggu/Desktop/atsectestvectors/testvectors", "Directory of formatted vector-set input files.")
	// 1188
	inputFileDirectory             = flag.String("in", "/Users/shanggu/Desktop/atsectestvectors/001/testvectors", "Directory of formatted vector-set input files.")
	outputFileDirectory            = flag.String("out", "/tmp/atsec", "Directory of formatted vector-set input files.")
	testVectorRequestJsonFileName  = flag.String("tr", "testvector-request.json", "TBD")
	testVectorExpectedJsonFileName = flag.String("te", "testvector-expected.json", "TBD")
	algorithmIdFilter              = flag.String("afilter", "KAS-FFC-SSC", "Algorithm id used for filter.")
	needCompression                = flag.Bool("compress", false, "Compress all files under the output directory.")
	// 1 - 300 AES cdrbg
	// 295 - 400 SHA HMAC ECDSA RSA
	// ECDSA -
	startNumOfProcessedFilesLimit = flag.Int("flimitStart", 363, "Only process starting from this number.")
	numOfProcessedFilesLimit      = flag.Int("flimit", 363, "Only process up to the number of test vector files.")
	shouldBeVerbose               = flag.Bool("verbose", false, "Print more verbose info.")
)

var numOfProcessedFiles = 0
var numOfSkippedFiles = 0

// testmodulewrapper has below primitives that modulewrapper does not have.
var modulewrapperMap = map[string]string{
	"ACVP-AES-XTS": "testmodulewrapper",
	"KDF":          "testmodulewrapper",
}

func formatFileName(algoId string, filename string, outputDir string) string {
	strs := strings.Split(filename, "/")
	if len(strs) < 3 {
		log.Printf("Warn: %s does not meet expected format.", filename)
		return ""
	}
	l := len(strs)
	return outputDir + "/" + algoId + "_" + strings.Join(strs[l - 3:], "_")
}

func getWrapper(filename string) string {
	for key, value := range modulewrapperMap {
		if strings.Contains(filename, key) {
			return value
		}
	}
	return "modulewrapper"
}

func compressFile(fileToCompress string, result *bytes.Buffer, isLastFile bool) {
	// -k keep input file
	cmd := exec.Command("bzip2", "-k", fileToCompress)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		log.Fatal("Failed to compressing file.", err)
	}
	if !strings.HasSuffix(fileToCompress, *testVectorRequestJsonFileName) {
		return
	}
	wrapperName := getWrapper(fileToCompress)
	expectedVectorFileName := strings.ReplaceAll(fileToCompress, *testVectorRequestJsonFileName, *testVectorExpectedJsonFileName)
	if _, err := os.Stat(expectedVectorFileName); os.IsNotExist(err) {
		(*result).WriteString(fmt.Sprintf("{\"Wrapper\": \"%s\", \"In\": \"%s.bz2\"}", wrapperName, fileToCompress))
	} else {
		configLine := fmt.Sprintf("{\"Wrapper\": \"%s\", \"In\": \"%s.bz2\", \"Out\": \"%s.bz2\"}", wrapperName, fileToCompress, expectedVectorFileName)
		(*result).WriteString(configLine)
	}
	if isLastFile {
		result.WriteString("\n")
	} else {
		result.WriteString(",\n")
	}
}

func compressFiles(dirName string) {
	if !(*needCompression) {
		return
	}
	var result bytes.Buffer
	result.WriteString("[\n")
	files, err := ioutil.ReadDir(dirName)
	if err != nil {
		log.Fatal(err)
	}
	files_len := len(files)
	for i, f := range files {
		nextPath := dirName + "/" + f.Name()
		compressFile(nextPath, &result, (i == (files_len - 1)))
	}
	result.WriteString("]\n")
	testJsonFileName := dirName + "/awslc-test.json"
	wfErr := ioutil.WriteFile(testJsonFileName, result.Bytes(), 0644)
	if wfErr != nil {
		log.Fatal("Failed to write %s.", testJsonFileName, wfErr)
	}
}

func processExpectedTestFile(algoId string, filename string, outputDir string) {

	var result bytes.Buffer
	err := subprocess.ProcessExpectedTestDataWithBsslFormat(filename, &result)

	if err != nil {
		log.Printf("Warn: failed to process %s", filename, err)
		return
	}

	outputExpectedFileName := formatFileName(algoId, filename, outputDir)

	if outputExpectedFileName != "" {
		err = ioutil.WriteFile(outputExpectedFileName, result.Bytes(), 0644)
		if err != nil {
			log.Fatal("Failed to write %s.", outputExpectedFileName, err)
		}
	}
}

// Move files to target folder.
// This provides some information needed when doing compression and generating json configuration.
func processTestVectorRequest(filename string, outputDir string) error {
	numOfProcessedFiles++

	if numOfProcessedFiles < *startNumOfProcessedFilesLimit {
		numOfSkippedFiles++
		if *shouldBeVerbose {
			log.Printf("Skip below start point files %s", filename)
		}
		return nil
	}

	if common.SkipKnwonFailedFiles(filename) {
		numOfSkippedFiles++
		if *shouldBeVerbose {
			log.Printf("Skip known failed files %s", filename)
		}
		return nil
	}

	jsonBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	var elements []json.RawMessage
	if err := json.Unmarshal(jsonBytes, &elements); err != nil {
		return err
	}

	// There must be at least one element in the file.
	if len(elements) < 1 {
		return errors.New("JSON input is empty")
	}
	var header json.RawMessage
	if common.LooksLikeHeaderElement(elements[0]) {
		header, elements = elements[0], elements[1:]
		if len(elements) == 0 {
			return errors.New("JSON input is empty")
		}
	}

	algoId, skip := subprocess.ShouldSkip(filename, elements)
	if len(*algorithmIdFilter) > 0 && algoId != (*algorithmIdFilter) {
		numOfSkippedFiles++
		return nil
	}
	if skip {
		log.Printf("Skip %d %s %s", numOfProcessedFiles, algoId, filename)
		numOfSkippedFiles++
		return nil
	}
	if algoId == "ECDSA" && subprocess.IsKeyGen(elements) {
	    numOfSkippedFiles++
		return nil
	}

	log.Printf("Process %d %s %s", numOfProcessedFiles, algoId, filename)

	var result bytes.Buffer
	result.WriteString("[")

	if header != nil {
		headerBytes, err := json.MarshalIndent(header, "", "    ")
		if err != nil {
			return err
		}
		result.Write(headerBytes)
		result.WriteString(",")
	}

	for i, element := range elements {
		elementBytes, err := json.MarshalIndent(element, "", "    ")
		if err != nil {
			return err
		}

		if i != 0 {
			result.WriteString(",")
		}
		result.Write(elementBytes)
	}

	result.WriteString("]\n")

	onlyTestVector := false
	fileNameOfExpectedTestVector := strings.ReplaceAll(filename, *testVectorRequestJsonFileName, *testVectorExpectedJsonFileName)
	if _, err := os.Stat(fileNameOfExpectedTestVector); os.IsNotExist(err) {
		onlyTestVector = true
	}
	outputTestVectorFileName := formatFileName(algoId, filename, outputDir)

	if outputTestVectorFileName != "" {
		err = ioutil.WriteFile(outputTestVectorFileName, result.Bytes(), 0644)
		if err != nil {
			log.Fatal("Failed to write %s.", outputTestVectorFileName, err)
		}
		if !onlyTestVector {
			inputExpectedVectorFileName := strings.ReplaceAll(filename, *testVectorRequestJsonFileName, *testVectorExpectedJsonFileName)
			processExpectedTestFile(algoId, inputExpectedVectorFileName, outputDir)
		}
	}

	return nil
}

func processDirAndFile(pathName string, outputDir string) {
	fi, err := os.Stat(pathName)
	if err != nil {
		log.Fatal(err)
	}
	switch mode := fi.Mode(); {
	case mode.IsDir():
		files, err := ioutil.ReadDir(pathName)
		if err != nil {
			log.Fatal(err)
		}
		fileNames := make([]string, len(files))
		for i, f := range files {
			fileNames[i] = pathName + "/" + f.Name()
		}

		sort.Strings(fileNames)

		for i := 0; i < len(fileNames); i++ {
			processDirAndFile(fileNames[i], outputDir)
		}

	case mode.IsRegular():
		if strings.HasSuffix(pathName, *testVectorRequestJsonFileName) {
			if numOfProcessedFiles >= *numOfProcessedFilesLimit {
				return
			}
			err := processTestVectorRequest(pathName, outputDir)
			if err != nil {
				log.Printf("Warn: err returns when process %s", pathName, err)
			}
		}
	}
}

func main() {
	flag.Parse()
	// Remove date and time.
	log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))

	if *inputFileDirectory == "" {
		log.Fatal("'in-dir' is required.")
	}

	absOutDir, e1 := filepath.Abs(*outputFileDirectory)
	if e1 != nil {
		log.Fatal("Failed to get abs of output dir.", e1)
	}
	e2 := os.RemoveAll(absOutDir)
	log.Printf("Removing all files under %s.", absOutDir)
	if e2 != nil {
		log.Fatal("Failed to remove all output file directory.", e2)
	}
	os.MkdirAll(absOutDir, 0755)

	absInDir, e3 := filepath.Abs(*inputFileDirectory)
	if e3 != nil {
		log.Fatal("Failed to get abs of in dir.", e3)
	}
	processDirAndFile(absInDir, absOutDir)
	if numOfProcessedFiles >= *numOfProcessedFilesLimit {
		log.Printf("Reach the process limit.")
	}
	log.Printf("numOfSkippedFiles %d", numOfSkippedFiles)
	compressFiles(absOutDir)
}
