package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/xml"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	_ "log"
	"math/rand"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"GoWeb/SiebelMaintenance/util/date"
	"GoWeb/SiebelMaintenance/util/ldap"

	"github.com/BurntSushi/toml"
	"github.com/julienschmidt/httprouter"
	"github.com/sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
)

// exposed variables should start with CAPS letter

type session struct {
	un           string
	lastActivity time.Time
}

type status struct {
	Message      string
	ProcessBegin bool
	SRNumber     string
}

type ListOfF5ActionLight struct {
	XMLName       xml.Name `xml:"ListOfF5ActionLight,omitempty"`
	F5ActionLight struct {
		Comment CdataString `xml:"Comment,omitempty"`
		GUID    string      `xml:"F5GUID,omitempty"`
		Planned string      `xml:"Planned,omitempty"`
		Type    string      `xml:"Type,omitempty"`
	} `xml:"F5ActionLight,omitempty"`
}

type SRDetail struct {
	SerialNumber     string
	ProblemStatement string
	SRNumber         string
	Account          string
	Product          string
	Version          string
	Status           string
	SubStatus        string
	Severity         string
	Source           string
	Email            string
	CaseCreatedBy    string
	Phone            string
	FirstName        string
	LastName         string
	CaseNote         string
}

type ServerMaintanance struct {
	XMLName                xml.Name `xml:"SiebelMessage"`
	MessageId              string   `xml:"MessageId,attr"`
	IntObjectName          string   `xml:"IntObjectName,attr"`
	MessageType            string   `xml:"MessageType,attr"`
	IntObjectFormat        string   `xml:"IntObjectFormat,attr"`
	ListOfF5ServiceRequest struct {
		ServiceRequestThin struct {
			SerialNumber        string `xml:"F5ApplianceSerialNumber"`
			Product             string `xml:"F5Product,omitempty"`
			Version             string `xml:"F5ProductVersion,omitempty"`
			Account             string `xml:"AccountLocation,omitempty"`
			Source              string `xml:"Source,omitempty"`
			Status              string `xml:"Status,omitempty"`
			Severity            string `xml:"Severity,omitempty"`
			Phone               string `xml:"RequestorBusinessPhone,omitempty"`
			Email               string `xml:"ContactEmail,omitempty"`
			ProblemStatement    string `xml:"Abstract,omitempty"`
			CreatedByName       string `xml:"CreatedByName,omitempty"`
			CreatedDate         string `xml:"F5CaseCreatedDate,omitempty"`
			UpdatedDate         string `xml:"F5CaseUpdatedDate,omitempty"`
			IntegrationId       string `xml:"IntegrationId,omitempty"`
			SRNumber            string `xml:"SRNumber,omitempty"`
			ListOfF5ActionLight *ListOfF5ActionLight
		} `xml:"ServiceRequestThin"`
	} `xml:"ListOfF5ServiceRequest"`
}

//LastName         string `xml:"lastName"`
//FirstName        string `xml:"firstName"`
//SubStatus        string `xml:"subStatus"`
//Owner            string `xml:"owner"`

type ServerMaintananceUpdate struct {
	XMLName                xml.Name `xml:"SiebelMessage"`
	MessageId              string   `xml:"MessageId,attr"`
	IntObjectName          string   `xml:"IntObjectName,attr"`
	MessageType            string   `xml:"MessageType,attr"`
	IntObjectFormat        string   `xml:"IntObjectFormat,attr"`
	ListOfF5ServiceRequest struct {
		ServiceRequestThin struct {
			Email               string `xml:"ContactEmail"`
			SRNumber            string `xml:"SRNumber"`
			Severity            string `xml:"Severity,omitempty"`
			Phone               string `xml:"RequestorBusinessPhone"`
			ListOfF5ActionLight struct {
				F5ActionLight struct {
					Comment CdataString `xml:"Comment"`
					GUID    string      `xml:"F5GUID"`
					Planned string      `xml:"Planned"`
					Type    string      `xml:"Type"`
				} `xml:"F5ActionLight"`
			} `xml:"ListOfF5ActionLight,omitempty"`
		} `xml:"ServiceRequestThin"`
	} `xml:"ListOfF5ServiceRequest"`
}

type CdataString struct {
	Value string `xml:",cdata"`
}

type IHandler struct{}

type Config struct {
	Cookie          cookie
	Server          server
	ActiveDirectory activeDirectory
	Siebel          siebel
	Logger          logger
}
type cookie struct {
	CookieLength int
	CookieName   string
}

type server struct {
	HttpPort  int
	HttpsPort int
	CertName  string
	KeyName   string
}

type activeDirectory struct {
	Base     string
	Host     string
	Port     int
	UseSSL   bool
	BindUser string
}

type siebel struct {
	ServiceRequestPath    string
	ServiceRequestFTPPath string
}
type logger struct {
	LoggerFile string
	LogLevel   string
}

type srIndex struct {
	Index                string
	Status               string
	ServiceRequestNumber string
	Date                 string
	FileName             string
}

var tpl *template.Template
var userSessionsCleaned time.Time
var userSessions = map[string]session{} // session ID, session
var conf Config
var logme = logrus.New()
var activeDirectoryPassword string
var loginUser string

func init() {
	tpl = template.Must(template.ParseGlob("templates/*"))
	userSessionsCleaned = time.Now()

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

	activeDirectoryPassword = getPwd()

	router := httprouter.New()

	router.GET("/siebel/login", login)
	router.POST("/siebel/login", login)

	router.GET("/siebel/index", index)
	router.GET("/siebel/lookup", lookup)
	router.GET("/siebel/new", serviceRequestNew)
	router.POST("/siebel/new", serviceRequestNew)
	router.GET("/siebel/update", serviceRequestUpdate)
	router.POST("/siebel/update", serviceRequestUpdate)
	router.GET("/siebel/srindex", srList)
	router.GET("/siebel/srdetail", srDetail)

	router.ServeFiles("/static/*filepath", http.Dir("static"))

	http.Handle("/favicon.ico", http.NotFoundHandler())

	//go http.ListenAndServe(strings.Join([]string{":",strconv.Itoa(conf.Server.HttpPort)},""), router)

	//err := http.ListenAndServeTLS(strings.Join([]string{":",strconv.Itoa(conf.Server.HttpsPort)},""), conf.Server.CertName, conf.Server.KeyName, router)
	//if err != nil {
	//log.Fatal(err)
	//}

	tconf := &tls.Config{}
	cert, err := tls.LoadX509KeyPair(conf.Server.CertName, conf.Server.KeyName)

	if err != nil {
		logme.Fatal(err)
	}

	tconf.Certificates = append(tconf.Certificates, cert)
	tconf.BuildNameToCertificate()

	go func() {

		logme.Fatal(http.ListenAndServe(strings.Join([]string{":", strconv.Itoa(conf.Server.HttpPort)}, ""), IHandler{}))
	}()

	sserv := http.Server{
		Addr:      strings.Join([]string{":", strconv.Itoa(conf.Server.HttpsPort)}, ""),
		Handler:   router,
		TLSConfig: tconf,
	}

	logme.Fatal(sserv.ListenAndServeTLS("", ""))

}

func getPwd() string {
	fmt.Println("")
	// Prompt the user to enter a password
	fmt.Print("Enter a Active directory password for " + conf.ActiveDirectory.BindUser + ": ")
	// We will use this to store the users input
	var pwd string
	// Read the users input
	_, err := fmt.Scan(&pwd)
	if err != nil {
		logme.Fatal(err)
	}
	fmt.Println("")
	return pwd
}

func (ih IHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	hostdom := strings.Split(r.Host, ":")[0]
	http.Redirect(w, r, "https://"+hostdom+strings.Join([]string{":", strconv.Itoa(conf.Server.HttpsPort)}, "")+r.URL.Path, http.StatusFound)
}

func login(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {

	if alreadyLoggedIn(w, req) {
		err := tpl.ExecuteTemplate(w, "index.gohtml", nil)
		HandleError(w, err)
		return
	}

	if req.Method == "GET" {

		formStatus := status{
			Message:      "",
			ProcessBegin: true,
			SRNumber:     "",
		}

		err := tpl.ExecuteTemplate(w, "login.gohtml", formStatus)
		HandleError(w, err)
	} else {

		userName := LDAP_Authenticate(req.FormValue("userName"), req.FormValue("password"))

		if userName != "" {
			c := &http.Cookie{
				Name:  conf.Cookie.CookieName,
				Value: userName,
			}
			c.MaxAge = conf.Cookie.CookieLength
			http.SetCookie(w, c)
			userSessions[c.Value] = session{userName, time.Now()}

			//showSessions()

			loginUser = req.FormValue("userName")

			err := tpl.ExecuteTemplate(w, "index.gohtml", nil)
			HandleError(w, err)
		} else {

			formStatus := status{
				Message:      "Invalid Login",
				ProcessBegin: false,
				SRNumber:     "",
			}
			err := tpl.ExecuteTemplate(w, "login.gohtml", formStatus)
			HandleError(w, err)
		}
	}

}

func logout(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	fmt.Println("log out")
	c, _ := req.Cookie(conf.Cookie.CookieName)
	// delete the session
	delete(userSessions, c.Value)
	// remove the cookie
	c = &http.Cookie{
		Name:   conf.Cookie.CookieName,
		Value:  "",
		MaxAge: -1,
	}
	http.SetCookie(w, c)

	// clean up userSessions
	if time.Now().Sub(userSessionsCleaned) > (time.Second * 30) {
		go cleanSessions()
	}

	http.Redirect(w, req, "/siebel/login", http.StatusSeeOther)
}

func index(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {

	if !alreadyLoggedIn(w, req) {
		http.Redirect(w, req, "/siebel/login", http.StatusSeeOther)
		return
	}

	err := tpl.ExecuteTemplate(w, "index.gohtml", nil)
	HandleError(w, err)
}

func lookup(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {

	if !alreadyLoggedIn(w, req) {
		http.Redirect(w, req, "/siebel/login", http.StatusSeeOther)
		return
	}
	err := tpl.ExecuteTemplate(w, "lookupsr.gohtml", nil)
	HandleError(w, err)
}

func serviceRequestNew(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {

	if !alreadyLoggedIn(w, req) {
		http.Redirect(w, req, "/siebel/login", http.StatusSeeOther)
		return
	}

	if req.Method == "GET" {

		formStatus := status{
			Message:      "success",
			ProcessBegin: true,
			SRNumber:     "",
		}

		err := tpl.ExecuteTemplate(w, "new.gohtml", formStatus)
		HandleError(w, err)
	} else {

		//currentTime := time.Now()
		//secs := currentTime.Unix()
		randomNumber := generateRandomNumber()
		uniqueNumber := strconv.FormatInt(randomNumber, 10) //convert int64 to string should use  10 to get the right correct format

		writeFormDataToFile(w, req, uniqueNumber, "New")

		formStatus := status{
			Message:      "success",
			ProcessBegin: false,
			SRNumber:     "CA" + uniqueNumber,
		}

		tpl.ExecuteTemplate(w, "new.gohtml", formStatus)

	}

}

func serviceRequestUpdate(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {

	if !alreadyLoggedIn(w, req) {
		http.Redirect(w, req, "/siebel/login", http.StatusSeeOther)
		return
	}
	if req.Method == "GET" {

		formStatus := status{
			Message:      "success",
			ProcessBegin: true,
			SRNumber:     "",
		}

		err := tpl.ExecuteTemplate(w, "update.gohtml", formStatus)
		HandleError(w, err)
	} else {

		//currentTime := time.Now()
		//secs := currentTime.Unix()
		randomNumber := generateRandomNumber()
		uniqueNumber := strconv.FormatInt(randomNumber, 10) //convert int64 to string should use  10 to get the right correct format

		writeFormDataToFile(w, req, uniqueNumber, "Update")

		formStatus := status{
			Message:      "success",
			ProcessBegin: false,
			SRNumber:     req.FormValue("srNumber"),
		}

		tpl.ExecuteTemplate(w, "update.gohtml", formStatus)

	}

}

type ByModTime []os.FileInfo

func (fis ByModTime) Len() int {
	return len(fis)
}

func (fis ByModTime) Swap(i, j int) {
	fis[i], fis[j] = fis[j], fis[i]
}

func (fis ByModTime) Less(i, j int) bool {
	return fis[i].ModTime().After(fis[j].ModTime())
}

func srList(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {

	if !alreadyLoggedIn(w, req) {
		http.Redirect(w, req, "/siebel/login", http.StatusSeeOther)
		return
	}

	if req.Method == "GET" {

		files, err := ioutil.ReadDir(conf.Siebel.ServiceRequestFTPPath)
		if err != nil {
			logme.Error(err)
		}
		//sort by modified date
		sort.Sort(ByModTime(files))

		var SrFiles = make([]srIndex, len(files))

		for ind, file := range files {

			// Split into two parts.
			result := strings.SplitN(file.Name(), "__", 2)

			SrFiles[ind].Index = strconv.Itoa(ind + 1)

			filePrefix := result[0][:1]
			if filePrefix == "N" {

				SrFiles[ind].Status = "New"
			} else if filePrefix == "U" {
				SrFiles[ind].Status = "Update"
			}
			SrFiles[ind].ServiceRequestNumber = result[0][1:]
			fileDate := result[1]
			pos := strings.Index(fileDate, ".")
			fileDate2 := fileDate[0:pos]
			//first 2 occurence
			fileDate2 = strings.Replace(fileDate2, "-", "/", 2)
			//remining 2 occurence
			fileDate2 = strings.Replace(fileDate2, "-", ":", 2)

			SrFiles[ind].Date = fileDate2
			SrFiles[ind].FileName = file.Name()

		}
		err = tpl.ExecuteTemplate(w, "srindex.gohtml", SrFiles)
		HandleError(w, err)
	}

}

func srDetail(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {

	if !alreadyLoggedIn(w, req) {
		http.Redirect(w, req, "/siebel/login", http.StatusSeeOther)
		return
	}

	if req.Method == "GET" {
		params := req.URL.Query()["sr"]
		inFile, _ := os.Open(conf.Siebel.ServiceRequestFTPPath + string(os.PathSeparator) + params[0])
		defer inFile.Close()
		formData := &SRDetail{}

		scanner := bufio.NewScanner(inFile)
		scanner.Split(bufio.ScanLines)

		for scanner.Scan() {
			//fmt.Println(scanner.Text())
			readLine := strings.SplitN(scanner.Text(), "=", 2)
			if readLine[0] == "SerialNumber" {
				formData.SerialNumber = readLine[1]
			} else if readLine[0] == "Account" {
				formData.Account = readLine[1]
			} else if readLine[0] == "Product" {
				formData.Product = readLine[1]
			} else if readLine[0] == "Version" {
				formData.Version = readLine[1]
			} else if readLine[0] == "Status" {
				formData.Status = readLine[1]
			} else if readLine[0] == "SubStatus" {
				formData.SubStatus = readLine[1]
			} else if readLine[0] == "Severity" {
				formData.Severity = readLine[1]
			} else if readLine[0] == "Source" {
				formData.Source = readLine[1]
			} else if readLine[0] == "Email" {
				formData.Email = readLine[1]
			} else if readLine[0] == "CaseCreatedBy" {
				formData.CaseCreatedBy = readLine[1]
			} else if readLine[0] == "Phone" {
				formData.Phone = readLine[1]
			} else if readLine[0] == "FirstName" {
				formData.FirstName = readLine[1]
			} else if readLine[0] == "LastName" {
				formData.LastName = readLine[1]
			} else if readLine[0] == "ProblemStatement" {
				formData.ProblemStatement = readLine[1]
			} else if readLine[0] == "CaseNote" {
				formData.CaseNote = readLine[1]
			} else if readLine[0] == "ServiceRequestNumber" {
				formData.SRNumber = readLine[1]
			}

		}
		err := tpl.ExecuteTemplate(w, "srdetail.gohtml", formData)
		HandleError(w, err)
	}
}

func writeFormDataToFile(w http.ResponseWriter, req *http.Request, uniqueNumber string, action string) {

	var fileName string
	var srNumber string

	formData := &ServerMaintanance{}

	if action == "Update" {
		fileName = "U" + req.FormValue("srNumber")
		srNumber = req.FormValue("srNumber")
	} else if action == "New" {
		fileName = "NCA" + uniqueNumber
		srNumber = "CA" + uniqueNumber
		formData.ListOfF5ServiceRequest.ServiceRequestThin.IntegrationId = "CA" + uniqueNumber
		formData.ListOfF5ServiceRequest.ServiceRequestThin.CreatedDate = GetToday(date.ConvertFormat("mm/dd/yyyy HH:MM:SS"))
	}

	req.ParseForm()

	/*for k, v := range req.Form {
		fmt.Println("key:", k)
		fmt.Println("val:", strings.Join(v, ""))
	}*/

	formData.MessageId = "1-24F4L8"
	formData.IntObjectName = "F5 Service Request Thin"
	formData.MessageType = "Integration Object"
	formData.IntObjectFormat = "Siebel Hierarchical"
	formData.ListOfF5ServiceRequest.ServiceRequestThin.SerialNumber = req.FormValue("serialNumber")
	formData.ListOfF5ServiceRequest.ServiceRequestThin.Product = req.FormValue("product")
	formData.ListOfF5ServiceRequest.ServiceRequestThin.Version = req.FormValue("version")
	formData.ListOfF5ServiceRequest.ServiceRequestThin.Account = req.FormValue("account")
	//formData.ListOfF5ServiceRequest.ServiceRequestThin.LastName = req.FormValue("lastName")
	//formData.ListOfF5ServiceRequest.ServiceRequestThin.FirstName = req.FormValue("firstName")
	formData.ListOfF5ServiceRequest.ServiceRequestThin.Source = req.FormValue("source")
	formData.ListOfF5ServiceRequest.ServiceRequestThin.Status = req.FormValue("status")
	formData.ListOfF5ServiceRequest.ServiceRequestThin.Severity = req.FormValue("severity")
	formData.ListOfF5ServiceRequest.ServiceRequestThin.Phone = req.FormValue("phone")
	formData.ListOfF5ServiceRequest.ServiceRequestThin.Email = req.FormValue("email")
	formData.ListOfF5ServiceRequest.ServiceRequestThin.ProblemStatement = req.FormValue("problemStatement")
	formData.ListOfF5ServiceRequest.ServiceRequestThin.CreatedByName = loginUser
	formData.ListOfF5ServiceRequest.ServiceRequestThin.UpdatedDate = GetToday(date.ConvertFormat("mm/dd/yyyy HH:MM:SS"))
	formData.ListOfF5ServiceRequest.ServiceRequestThin.SRNumber = srNumber
	//formData.ListOfF5ServiceRequest.ServiceRequestThin.SubStatus = req.FormValue("subStatus")
	//formData.ListOfF5ServiceRequest.ServiceRequestThin.Owner = req.FormValue("owner")

	if req.FormValue("caseNote") != "" {

		caseNoteData := &ListOfF5ActionLight{}

		caseNoteData.F5ActionLight.Comment = CdataString{Value: req.FormValue("caseNote")}
		caseNoteData.F5ActionLight.GUID = uniqueNumber
		caseNoteData.F5ActionLight.Planned = GetToday(date.ConvertFormat("mm/dd/yyyy HH:MM:SS"))
		caseNoteData.F5ActionLight.Type = "Notes"

		formData.ListOfF5ServiceRequest.ServiceRequestThin.ListOfF5ActionLight = caseNoteData

	}

	//formData := &ServerMaintanance{SerialNumber: req.FormValue("serialNumber"), Product: req.FormValue("product"), Version: req.FormValue("version"), Account: req.FormValue("account"), LastName: req.FormValue("lastName"), FirstName: req.FormValue("firstName"), Source: req.FormValue("source"), Status: req.FormValue("status"), SubStatus: req.FormValue("subStatus"), Owner: req.FormValue("owner"), Severity: req.FormValue("severity"), Phone: req.FormValue("phone"), Email: req.FormValue("email"), ProblemStatement: req.FormValue("problemStatement"), CreatedDate: currentTime.Format("2006-Jan-02 15:04:05")}
	xmlString, err := xml.MarshalIndent(formData, "  ", "    ")

	HandleError(w, err)

	var buffer bytes.Buffer

	buffer.WriteString(conf.Siebel.ServiceRequestPath)
	buffer.WriteString(fileName)
	buffer.WriteString("__")
	//buffer.WriteString(strconv.FormatInt(secs, 10))
	dt := GetToday(date.ConvertFormat("mm/dd/yyyy HH:MM:SS"))
	dt = strings.Replace(dt, ":", "-", -1)
	dt = strings.Replace(dt, "/", "-", -1)
	buffer.WriteString(dt)
	buffer.WriteString(".txt")
	filename := buffer.String()
	file, err := os.Create(filename)
	HandleError(w, err)

	defer file.Close()

	xmlWriter := io.Writer(file)
	//xmlWriter.Write([]byte(xml.Header))
	xmlWriter.Write([]byte("<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n"))

	xmlWriter.Write(xmlString)

	//save in ftp location
	//copyFile(filename)
	var buffer2 bytes.Buffer
	buffer2.WriteString(conf.Siebel.ServiceRequestFTPPath)
	buffer2.WriteString(fileName)
	buffer2.WriteString("__")
	buffer2.WriteString(dt)
	buffer2.WriteString(".txt")

	filename2 := buffer2.String()
	file2, err2 := os.Create(filename2)
	HandleError(w, err2)

	defer file2.Close()

	var buffer3 bytes.Buffer

	buffer3.WriteString("ServiceRequestNumber=" + srNumber + "\n")
	buffer3.WriteString("SerialNumber=" + req.FormValue("serialNumber") + "\n")
	buffer3.WriteString("Account=" + req.FormValue("account") + "\n")
	buffer3.WriteString("Product=" + req.FormValue("product") + "\n")
	buffer3.WriteString("Version=" + req.FormValue("version") + "\n")
	buffer3.WriteString("Status=" + req.FormValue("status") + "\n")
	buffer3.WriteString("SubStatus=" + req.FormValue("subStatus") + "\n")
	buffer3.WriteString("Severity=" + req.FormValue("severity") + "\n")
	buffer3.WriteString("Source=" + req.FormValue("source") + "\n")
	buffer3.WriteString("Email=" + req.FormValue("email") + "\n")
	buffer3.WriteString("CaseCreatedBy=" + loginUser + "\n")
	buffer3.WriteString("Phone=" + req.FormValue("phone") + "\n")
	buffer3.WriteString("FirstName=" + req.FormValue("firstName") + "\n")
	buffer3.WriteString("LastName=" + req.FormValue("lastName") + "\n")
	buffer3.WriteString("ProblemStatement=" + req.FormValue("problemStatement") + "\n")

	buffer3.WriteString("CaseNote=" + strings.Replace(req.FormValue("caseNote"), "\n", "<br/>", -1) + "\n")

	fileWriter := io.Writer(file2)
	fileWriter.Write([]byte(buffer3.String()))
}

func copyFile(fileName string) {

	from, err := os.Open(fileName)

	if err != nil {
		logme.Error(err)

	}
	defer from.Close()
	//FileName contains fullpath replacing 'in' file path to 'ftp' path
	r := strings.NewReplacer(conf.Siebel.ServiceRequestPath, conf.Siebel.ServiceRequestFTPPath)
	resultFile := r.Replace(fileName)

	// Create new file
	to, err := os.Create(resultFile)

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

func HandleError(w http.ResponseWriter, err error) {
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		logme.Errorln(err)
	}
}

func generateRandomNumber() int64 {
	return time.Now().UnixNano() / int64(time.Millisecond)
}

/*func generateRandomNumber() int {
	rand.Seed(time.Now().UnixNano())
	randomNum := random(100000000, 900000000)
	//fmt.Printf("Random Num: %d\n", randomNum)
	return randomNum

}*/
func random(min int, max int) int {
	return rand.Intn(max-min) + min
}

func GetToday(format string) (todayString string) {
	today := time.Now()
	todayString = today.Format(format)
	return
}

func LDAP_Authenticate(userName, password string) string {
	var credentials = ""

	client := &ldap.LDAPClient{
		Base:   conf.ActiveDirectory.Base,
		Host:   conf.ActiveDirectory.Host,
		Port:   conf.ActiveDirectory.Port,
		UseSSL: conf.ActiveDirectory.UseSSL,
		//BindDN:       "uid=_PrdSiebelADSIUser,ou=People,DC=Olympus,DC=F5Net,DC=com",
		//BindPassword: "4herY467kl", //prod
		BindDN: conf.ActiveDirectory.BindUser,
		//BindPassword: conf.ActiveDirectory.BindPassword,
		BindPassword: activeDirectoryPassword,
		UserFilter:   "(sAMAccountName=%s)",
		//GroupFilter:  "(memberUid=%s)",
		Attributes: []string{"sAMAccountName", "givenName", "sn", "mail", "cn"},
	}
	defer client.Close()

	ok, user, err := client.Authenticate(userName, password)
	if err != nil {
		//log.Fatalf("Error authenticating user %s: %+v", "username", err)
		//fmt.Println("Error authenticating user %s: %+v", "username", err)

		credentials = ""
	} else if !ok {
		//log.Fatalf("Authenticating failed for user %s", "username")
		//fmt.Println("Authenticating failed for user %s", "username")
		credentials = ""
	} else if user["cn"] != "" {

		credentials = user["cn"]
	} else {
		credentials = ""
	}

	//log.Printf("User: %+v", user)
	//log.Printf("User cn", user["cn"])
	if credentials != "" {
		logme.Infof("User: %+v", user)
	} else {
		logme.Infof("User: %s - %s", userName, "invalid credentails")
	}

	return credentials
}

func alreadyLoggedIn(w http.ResponseWriter, req *http.Request) bool {
	c, err := req.Cookie(conf.Cookie.CookieName)
	if err != nil {
		return false
	}
	s, ok := userSessions[c.Value]
	if ok {
		s.lastActivity = time.Now()
		userSessions[c.Value] = s
	}

	// refresh session
	c.MaxAge = conf.Cookie.CookieLength
	http.SetCookie(w, c)
	return ok
}

func cleanSessions() {
	//fmt.Println("BEFORE CLEAN")
	//showSessions()
	for k, v := range userSessions {
		if time.Now().Sub(v.lastActivity) > (time.Second * 30) {
			delete(userSessions, k)
		}
	}
	userSessionsCleaned = time.Now()
	//fmt.Println("AFTER CLEAN")
	//showSessions()
}

// for demonstration purposes
func showSessions() {

	for k, v := range userSessions {
		fmt.Println(k, v.un)
	}
	fmt.Println("")
}
