package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strconv"

	"github.com/BurntSushi/toml"
	"github.com/sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
)

// exposed variables should start with CAPS letter
type Config struct {
	SiebelService siebelService
	Logger        logger
}
type siebelService struct {
	ServiceRequestPath   string
	ServiceErrorFilePath string
	ServiceEndpoint      string
}
type logger struct {
	LoggerFile string
	LogLevel   string
}

var conf Config
var logme = logrus.New()

func init() {
	configFile := flag.String("configFile", "defaultFilePath", "Pass config file path location")
	flag.Parse()

	//fmt.Printf("config file %+v", *configFile)

	if _, err := toml.DecodeFile(*configFile, &conf); err != nil {
		fmt.Println(err)
	}

	//fmt.Printf("%#v\n", conf)

	filename := conf.Logger.LoggerFile
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)

	if err != nil {
		// Cannot open log file. Logging to stderr
		fmt.Println(err)
	}
	logLevel := logrus.DebugLevel

	switch conf.Logger.LogLevel {
	case "Info":
		logLevel = logrus.InfoLevel
	case "Warn":
		logLevel = logrus.WarnLevel
	case "Error":
		logLevel = logrus.ErrorLevel
	default:
		logLevel = logrus.DebugLevel
	}

	logme = &logrus.Logger{
		Out:   f,
		Level: logLevel,
		Formatter: &prefixed.TextFormatter{
			DisableColors:   true,
			TimestampFormat: "2006-01-02 15:04:05",
			FullTimestamp:   true,
			ForceFormatting: true,
		},
	}

	//logme.Infof("Config Info %#v\n", conf)
}

func main() {

	client := NewSOAPClient(conf.SiebelService.ServiceEndpoint, true, nil)

	files, err := ioutil.ReadDir(conf.SiebelService.ServiceRequestPath)
	if err != nil {
		logme.Error(err)
	}

	logme.Info("Total Number of Sevice Requests ", len(files))
	logme.Info("SR Processing Started....")

	fmt.Println("Total Number of Sevice Requests ", len(files))
	fmt.Print("SR Processing Started....")

	var status string

	for _, file := range files {
		fmt.Print("..")
		logme.Info("Reading file: ", file.Name())
		srFilePath := conf.SiebelService.ServiceRequestPath + string(os.PathSeparator) + file.Name()
		fileData, _ := ioutil.ReadFile(srFilePath)

		//fmt.Print(string(fileData))

		fmt.Println("")
		logme.Error("Currently processing " + file.Name() + "...")
		fmt.Println("Currently processing " + file.Name() + "...")

		filePrefix := file.Name()[:1]
		if filePrefix == "N" {

			req := &CreateSR_Input{
				InStr: string(fileData),
			}

			res := &CreateSR_Output{}
			//For create call CreateSR only
			soapAction := strconv.Quote("document/http://siebel.com/CustomUI:CreateSR")

			if err := client.Call(soapAction, req, res); err != nil {
				fmt.Println("")
				fmt.Println(err)
				logme.Error(err)
				status = "error"

				copyFileToErrorLocation(file.Name())
			}

			if res.Status != "SUCCESS" {

				fmt.Println("")

				logme.Error("Error Code: ", res.ErrorCode)
				logme.Error("Error Message: ", res.ErrorMsg)
				logme.Error("Status: ", res.Status)

				fmt.Println("Error Code: ", res.ErrorCode)
				fmt.Println("Error Message: ", res.ErrorMsg)
				fmt.Println("Status: ", res.Status)

				status = "error"

				copyFileToErrorLocation(file.Name())

			}

		} else if filePrefix == "U" {
			req := &UpdateSR_Input{
				InStr: string(fileData),
			}

			res := &UpdateSR_Output{}
			//For update  call UpdateSR only
			soapAction := strconv.Quote("document/http://siebel.com/CustomUI:UpdateSR")

			if err := client.Call(soapAction, req, res); err != nil {
				fmt.Println("")
				fmt.Println(err)
				logme.Error(err)
				status = "error"
				copyFileToErrorLocation(file.Name())
			}

			if res.Status != "SUCCESS" {
				fmt.Println("")
				logme.Error("Error Code: ", res.ErrorCode)
				logme.Error("Error Message: ", res.ErrorMsg)
				logme.Error("Status: ", res.Status)

				fmt.Println("Error: ", res.ErrorCode)
				fmt.Println("Error Message: ", res.ErrorMsg)
				fmt.Println("Status: ", res.Status)

				status = "error"

				copyFileToErrorLocation(file.Name())

			}
		}

		deleteFile(file.Name())
	}

	fmt.Println("")
	if status == "error" {
		fmt.Println("SR Process Failed")
		logme.Error("SR Process Failed")
	} else {
		fmt.Println("SR Process Completed")
		logme.Info("SR Process Completed")
	}

}

func copyFileToErrorLocation(fileName string) {

	srcFilePath := conf.SiebelService.ServiceRequestPath + string(os.PathSeparator) + fileName
	targetFilePath := conf.SiebelService.ServiceErrorFilePath + string(os.PathSeparator) + fileName

	from, err := os.Open(srcFilePath)

	if err != nil {
		logme.Error(err)

	}
	defer from.Close()
	// Create new file
	to, err := os.Create(targetFilePath)

	if err != nil {
		logme.Error(err)

	}
	defer to.Close()

	// Copy the bytes to destination from source
	_, err = io.Copy(to, from)
	if err != nil {
		logme.Error(err)
	}
	// Commit the file contents
	// Flushes memory to disk
	err = to.Sync()
	if err != nil {
		logme.Error(err)
	}
}
func deleteFile(fileName string) {
	srcFilePath := conf.SiebelService.ServiceRequestPath + string(os.PathSeparator) + fileName

	err := os.Remove(srcFilePath)
	if err != nil {
		logme.Error(err)
	}
}
