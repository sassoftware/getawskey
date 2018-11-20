package main

// *
// *  ------------------------------------------------------------------------------------
// *  * Copyright (c) SAS Institute Inc.
// *  *  Licensed under the Apache License, Version 2.0 (the "License");
// *  * you may not use this file except in compliance with the License.
// *  * You may obtain a copy of the License at
// *  *
// *  * http://www.apache.org/licenses/LICENSE-2.0
// *  *
// *  *  Unless required by applicable law or agreed to in writing, software
// *  * distributed under the License is distributed on an "AS IS" BASIS,
// *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// *  * See the License for the specific language governing permissions and
// *  limitations under the License.
// * ----------------------------------------------------------------------------------------
// *
// *

import (
	"encoding/base64"
	"encoding/xml"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/parnurzeal/gorequest"
	"github.com/robfig/config"
	"golang.org/x/crypto/ssh/terminal"
	krbauth "krb"
	"mfa"
)

// AWSDIR is the directory location for storing AWS Configs.
var AWSDIR string

// AWSKEYCONFIG is the config file used by getawskey
var AWSKEYCONFIG string
var awskeyconfigdef string

// AWSCREDENTIALS is the credentials file used by common AWS tools including awscli/boto/boto3.
var AWSCREDENTIALS string

// AWSCREDENTIALStmp var
var AWSCREDENTIALStmp string

// DEBUG Bool
var DEBUG bool

// MFA Bool if MFA is required
var MFA bool

// AWSCONFIG is a config file used by getawskey to store region/output preferences.
var AWSCONFIG string
var username string
var password string
var account string
var ver string
var err error
var principalArn string
var saml string
var testrun bool

// COMMENT config file comment
var COMMENT string

// SEPARATOR Config File separator
var SEPARATOR string

// ADFS Server
var ADFS string

//SessionDuration
var DURATION int64
var idpEndpoint string

// USERAGENT Browser user agent
var USERAGENT string

// KeyConfig is the struct which includes your profile information such as role_arn, principal_arn, and etc.
type KeyConfig struct {
	username     string
	password     string
	roleArn      string
	principalArn string
	output       string
	region       string
	idpEndpoint  string
}

//Create struct to hold xml values
type attr struct {
	Key   string   `xml:"Name,attr"`
	Value []string `xml:"AttributeValue,string"`
}
type samlr struct {
	XMLName xml.Name `xml:"Response"`
	Attrs   []attr   `xml:"Assertion>AttributeStatement>Attribute"`
}

// AddToConf adds a KeyConfig type to awskeyconfig.
func AddToConf(keyconfig KeyConfig, profile string, awskeyconfig *config.Config) *config.Config {
	awskeyconfig.AddSection(profile)
	awskeyconfig.AddOption(profile, "username", keyconfig.username)
	awskeyconfig.AddOption(profile, "password", keyconfig.password)
	awskeyconfig.AddOption(profile, "role_arn", keyconfig.roleArn)
	awskeyconfig.AddOption(profile, "principal_arn", keyconfig.principalArn)
	awskeyconfig.AddOption(profile, "output", keyconfig.output)
	awskeyconfig.AddOption(profile, "region", keyconfig.region)
	awskeyconfig.AddOption(profile, "idp_endpoint", keyconfig.idpEndpoint)
	return awskeyconfig
}

// GetCredentials -- Gets the domain\user and password from the input
// Arguments: None
// Returns:
//      Domain\User (string)
//      Password (string)
func GetCredentials() (string, string) {
	fmt.Print("Domain\\Username: ")
	var user string
	_, err := fmt.Scanln(&user)
	if err != nil {
		fmt.Println(err)
		if DEBUG {
			panic("Stack trace:")
		}
	}
	fmt.Print("Password: ")
	rawpass, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Println(err)
		if DEBUG {
			panic("Stack trace:")
		}
	}
	pass := string(rawpass[:])
	fmt.Println()
	return user, pass
}

// GetSAML -- Gets the SAML response from endpoint
// Arguments:
//      endpoint url (string)
//      username (string)
//      password (string)
// Returns:
//      saml (string)
func GetSAML(endpoint, username, password string) string {
	var resp gorequest.Response
	var body string
	var reqerror []error
	// Form the payload
	logindata := url.Values{}
	logindata.Set("UserName", username)
	logindata.Add("Password", password)
	payload := logindata.Encode()

	// Send the request
	request := gorequest.New()
	resp, body, reqerror = request.Post(endpoint).Send(payload).End()
	if reqerror != nil {
		fmt.Println(reqerror)
		if DEBUG {
			panic("Stack trace:")
		}
	}

	MFA, mfaStatus := mfa.IsMFA(body, resp, username, password)
	if MFA {
		resp, body, reqerror = request.Post(endpoint).
			Send(mfaStatus).
			End()
		if reqerror != nil {
			fmt.Println("Request error.")
			fmt.Println(reqerror)
			if DEBUG {
				panic("Stack trace:")
			}
		}
	}
	// Load up the response to parse
	doc, parseerror := goquery.NewDocumentFromReader(resp.Body)
	if parseerror != nil {
		fmt.Println(parseerror)
		if DEBUG {
			panic("Stack trace:")
		}
	}
	samlout := ""
	// Find the saml response and return it
	doc.Find("input[name=SAMLResponse]").Each(func(i int, s *goquery.Selection) {
		saml, exists := s.Attr("value")
		if exists {
			samlout = saml
		}
	})
	if len(samlout) == 0 {
		fmt.Println("Error getting saml")
		if DEBUG {
			panic("Stack trace:")
		}
		os.Exit(1)
	}

	return samlout
}

// GetSTSKeys -- Reaches out to AWS STS for temporary keys
// Arguments:
//      role arn (string)
//      principal arn (string)
//      saml response (string)
// Returns:
//      STS credentials (*sts.Credentials)
func GetSTSKeys(role string, princ string, DURATION int64, saml string) *sts.Credentials {
	// Make the client and config to us-east-1
	client := sts.New(session.New(), aws.NewConfig().WithRegion("us-east-1"))
	// Load up the params with SAML and role/princ arn
	params := &sts.AssumeRoleWithSAMLInput{
		SAMLAssertion:   aws.String(saml),
		RoleArn:         aws.String(role),
		PrincipalArn:    aws.String(princ),
		DurationSeconds: &DURATION,
	}
	// Make the call
	auth, err := client.AssumeRoleWithSAML(params)
	if err != nil {
		if strings.Contains(err.Error(), "exceeds the MaxSessionDuration") {
			if DURATION != 3600 {
				fmt.Printf("Error getting keys for %s with duration %d seconds, falling back to 3600 seconds\n", role, DURATION)
				creds := GetSTSKeys(role, princ, 3600, saml)
				return creds
			} else {
				// Realistically should never get here
				// But let's future proof in case AWS decides to lower the threshold below 3600
				fmt.Printf("Please set a -duration less than or equal to your role's MaxSessionDuration for: %s\n", role)
			}
		} else {
			fmt.Println("Unable to acquire a session token for " + role + "\n")
		}
		return nil
	}
	return auth.Credentials
}

// AWSAuth -- Auth with AWS with the SAML
// Arguments:
//      idp endpoint (string)
//      role arn (string)
//      principal arn (string)
// Returns:
//      STS credentials (*sts.Credentials)
func AWSAuth(idp, ADFS, USERAGENT, role, princ string, user string, pass string, rsaml string, passwordauth *bool, DURATION int64) (saml string, creds *sts.Credentials) {
	if rsaml == "" {
		if *passwordauth == false {
			saml = krbauth.AuthKerb(idp, ADFS, USERAGENT)
		} else {
			saml = GetSAML(idp, user, pass)
		}
	} else {
		saml = rsaml
	}
	creds = GetSTSKeys(role, princ, DURATION, saml)
	return saml, creds
}

// ListSections lists the available sections in AWSKEYCONFIG
func ListSections(COMMENT string, SEPARATOR string) []string {
	var sections []string
	conf, err := config.Read(AWSKEYCONFIG, COMMENT, SEPARATOR, false, true)
	if err != nil {
		fmt.Println(err)
		if DEBUG {
			panic("Stack trace:")
		}
	}
	sections = conf.Sections()
	return sections
}

// ReadConfig -- Reads the whole AWSKEYCONFIG file
// Arguments:
//      None
// Returns:
//      Keyconfig (KeyConfig)
func ReadConfig(profile string, COMMENT string, SEPARATOR string) KeyConfig {
	_, err := os.Stat(AWSKEYCONFIG)
	conf, err := config.Read(AWSKEYCONFIG, COMMENT, SEPARATOR, false, true)
	if err != nil {
		fmt.Println(err)
		if DEBUG {
			panic("Stack trace:")
		}
	}
	user, _ := conf.String(profile, "username")
	pass, _ := conf.String(profile, "password")
	role, _ := conf.String(profile, "role_arn")
	princ, _ := conf.String(profile, "principal_arn")
	output, _ := conf.String(profile, "output")
	region, _ := conf.String(profile, "region")
	endpoint, _ := conf.String(profile, "idp_endpoint")

	if user == "" || pass == "" {
		user = "None"
		pass = "None"
	}
	if user != "None" {
		if strings.Contains(user, "\\") {
			fmt.Println("Notice: saving username/password in plain text is deprecated: " + AWSKEYCONFIG)
		} else {
			fmt.Println("Please specify domain with user as follows for: " + AWSKEYCONFIG)
			fmt.Print("Domain\\Username: ")
			os.Exit(1)
		}
	}

	loadedconf := KeyConfig{
		username:     user,
		password:     pass,
		roleArn:      role,
		principalArn: princ,
		output:       output,
		region:       region,
		idpEndpoint:  endpoint,
	}
	return loadedconf
}

// CreateConfig -- Writes .aws/awskeyconfig
func CreateConfig(idpEndpoint, ADFS, USERAGENT string, createall *bool, passwordauth *bool, testrun *bool, COMMENT string, SEPARATOR string) string {
	var roleArn string
	var output string
	var region string
	var choice int
	var roleconfig KeyConfig
	var profileName string
	region = "us-east-1"
	output = "json"
	if *passwordauth == false {
		saml = krbauth.AuthKerb(idpEndpoint, ADFS, USERAGENT)
	} else {
		username, password = GetCredentials()
		saml = GetSAML(idpEndpoint, username, password)
	}
	decode, err := base64.StdEncoding.DecodeString(saml)
	if err != nil {
		fmt.Println(err)
		if DEBUG {
			panic("Stack trace:")
		}
	}
	v := new(samlr)
	err = xml.Unmarshal([]byte(decode), v)
	if err != nil {
		fmt.Printf("error: %v", err)
	}
	//
	awskeyconfig := config.New(COMMENT, SEPARATOR, false, true)
	var hasRoles int
	for s := 0; s < len(v.Attrs); s++ {
		if v.Attrs[s].Key == "https://aws.amazon.com/SAML/Attributes/Role" {
			hasRoles++
			if len(v.Attrs[s].Value) == 1 {
				roleArn = strings.Split(v.Attrs[s].Value[0], ",")[1]
				principalArn = strings.Split(v.Attrs[s].Value[0], ",")[0]
				profileName = "default"
				roleconfig = KeyConfig{
					username:     "None",
					password:     "None",
					roleArn:      roleArn,
					output:       output,
					region:       region,
					principalArn: principalArn,
					idpEndpoint:  idpEndpoint,
				}
				awskeyconfig = AddToConf(roleconfig, profileName, awskeyconfig)
			} else if *createall == true {
				for a := 0; a < len(v.Attrs[s].Value); a++ {
					roleArn = strings.Split(v.Attrs[s].Value[a], ",")[1]
					account = strings.Split(roleArn, ":")[4]
					principalArn = strings.Split(v.Attrs[s].Value[a], ",")[0]
					profileName := account + "-" + strings.Split(roleArn, "/")[1]
					roleconfig = KeyConfig{
						username:     "None",
						password:     "None",
						roleArn:      roleArn,
						output:       output,
						region:       region,
						principalArn: principalArn,
						idpEndpoint:  idpEndpoint,
					}
					fmt.Println("adding " + profileName + " to awskeyconfig")
					awskeyconfig = AddToConf(roleconfig, profileName, awskeyconfig)
				}
			} else {
				for a := 0; a < len(v.Attrs[s].Value); a++ {
					roleArn = strings.Split(v.Attrs[s].Value[a], ",")[1]
					fmt.Println("[ "+strconv.Itoa(a)+" ]: ", roleArn)
				}
				if *testrun == true {
					choice = 0
				} else {
					fmt.Print("Please choose a role to assume:  ")
					_, err = fmt.Scanln(&choice)
					if err != nil {
						fmt.Println(err)
						if DEBUG {
							panic("Stack trace:")
						}
					}
					fmt.Println("you selected: " + strconv.Itoa(choice))
				}
				roleArn = strings.Split(v.Attrs[s].Value[choice], ",")[1]
				principalArn = strings.Split(v.Attrs[s].Value[choice], ",")[0]
				profileName := "default"
				roleconfig = KeyConfig{
					username:     "None",
					password:     "None",
					roleArn:      roleArn,
					output:       output,
					region:       region,
					principalArn: principalArn,
					idpEndpoint:  idpEndpoint,
				}
				awskeyconfig = AddToConf(roleconfig, profileName, awskeyconfig)
				fmt.Println("Assuming role:  " + roleArn)
			}
		}
	}
	if hasRoles == 0 {
		fmt.Println("No Roles were found.  Please verify you have access")
		if DEBUG {
			panic("Stack trace:")
		}
		os.Exit(1)
	}
	err = awskeyconfig.WriteFile(AWSKEYCONFIG, 0644, "Created by getawskey.go")
	if err != nil {
		fmt.Println("Error saving the aws awskeyconfig file: " + AWSKEYCONFIG)
		if DEBUG {
			panic("Stack trace:")
		}
		os.Exit(1)
	}

	return saml
}

// WriteAWSConfigs -- Writes .aws/credentials and .aws/config
// Arguments:
//      STS Credentials (*sts.Credentials)
//      keyconfig (KeyConfig)
// Returns:
//      None
func WriteAWSConfigs(stscreds *sts.Credentials, keyconfig KeyConfig, profile string, COMMENT string, SEPARATOR string) {
	// Credentials
	var credentials *config.Config
	if _, err := os.Stat(AWSCREDENTIALS); os.IsNotExist(err) {
		//Create new credentils
		credentials = config.New(COMMENT, SEPARATOR, false, true)
	} else {
		//Read existing credentials
		credentials, err = config.Read(AWSCREDENTIALS, COMMENT, SEPARATOR, false, true)
		if err != nil {
			fmt.Println(err)
			if DEBUG {
				panic("Stack trace:")
			}
		}
	}

	if credentials.HasSection(profile) {
		//Append to existing section
	} else {
		//Create new section
		credentials.AddSection(profile)
	}
	credentials.AddOption(profile, "aws_access_key_id", *stscreds.AccessKeyId)
	credentials.AddOption(profile, "aws_secret_access_key", *stscreds.SecretAccessKey)
	credentials.AddOption(profile, "aws_session_token", *stscreds.SessionToken)
	credentials.AddOption(profile, "aws_security_token", *stscreds.SessionToken)
	credentials.AddOption(profile, "expiration", stscreds.Expiration.String())
	err = credentials.WriteFile(AWSCREDENTIALStmp, 0644, "Created by getawskey.go")
	if err != nil {
		fmt.Println("Error saving the aws credentials file")
		if DEBUG {
			panic("Stack trace:")
		}
		os.Exit(1)
	}
	//Rename credentials.new to credentials
	err = os.Rename(AWSCREDENTIALStmp, AWSCREDENTIALS)
	if err != nil {
		fmt.Println("Error renaming credentials file")
		if DEBUG {
			panic("Stack trace:")
		}
	}

	// Config
	var awsconfig *config.Config
	var configProfile string
	if profile == "default" {
		configProfile = profile
	} else {
		configProfile = "profile " + profile
	}
	if _, err := os.Stat(AWSCONFIG); os.IsNotExist(err) {
		//Create new awsconfig
		awsconfig = config.New(COMMENT, SEPARATOR, false, true)
	} else {
		//Read existing awsconfig
		awsconfig, err = config.Read(AWSCONFIG, COMMENT, SEPARATOR, false, true)
		if err != nil {
			fmt.Println(err)
			if DEBUG {
				panic("Stack trace:")
			}
		}
	}
	if awsconfig.HasSection(configProfile) {
		//Append to existing section
	} else {
		//Create new section
		awsconfig.AddSection(configProfile)
	}
	awsconfig.AddOption(configProfile, "region", keyconfig.region)
	awsconfig.AddOption(configProfile, "output", keyconfig.output)
	err = awsconfig.WriteFile(AWSCONFIG, 0644, "Created by getawskey.go")
	if err != nil {
		fmt.Println("Error saving the aws config file")
		if DEBUG {
			panic("Stack trace:")
		}
	}
}

func main() {
	COMMENT = "# "
	SEPARATOR = "="
	user, _ := user.Current()
	AWSDIR = filepath.Join(user.HomeDir, ".aws")
	awskeyconfigdef = filepath.Join(AWSDIR, "awskeyconfig")
	AWSCREDENTIALS = filepath.Join(AWSDIR, "credentials")
	AWSCREDENTIALStmp = filepath.Join(AWSDIR, "credentials.new")
	AWSCONFIG = filepath.Join(AWSDIR, "config")
	flag.StringVar(&AWSKEYCONFIG, "file", awskeyconfigdef, "use an alternate config file")
	flag.StringVar(&ADFS, "adfs", "example.yourcompany.com", "Specify ADFS cluster FQDN")
	flag.Int64Var(&DURATION, "duration", 3600, "Specify Session Duration (Seconds) up to the amount specified on the role. Example: 43200")
	flag.StringVar(&USERAGENT, "useragent", "MSIE 6.0; Windows NT", "Specify browser useragent compatible with your ADFS")
	createall := flag.Bool("createall", false, "Writes a config with all role_arn's you have permissions to")
	prompt := flag.Bool("prompt", false, "Prompt with list of accounts like on first run and overwrites profile DEFAULT, createall takes priority")
	passwordauth := flag.Bool("pass", false, "Authenticate using interactive or saved username/password")
	version := flag.Bool("version", false, "Print version and exit")
	flag.BoolVar(&DEBUG, "debug", false, "Print stack traces upon error and extra debugging information.")
	flag.Parse()
	var config KeyConfig
	var creds *sts.Credentials
	testrun = false
	idpEndpoint = "https://" + ADFS + "/adfs/ls/IdpInitiatedSignon.aspx?logintorp=urn:amazon:webservices"

	if *version == true {
		fmt.Println(majorver + "-" + ver)
		os.Exit(1)
	}
	if _, err := os.Stat(AWSDIR); os.IsNotExist(err) {
		fmt.Println(AWSDIR + " not found, creating...")
		os.Mkdir(AWSDIR, 0755)
	}

	_, err := os.Stat(AWSKEYCONFIG)
	if os.IsNotExist(err) || *createall == true || *prompt {
		fmt.Println("Creating " + AWSKEYCONFIG + "....\n")
		saml = CreateConfig(idpEndpoint, ADFS, USERAGENT, createall, passwordauth, &testrun, COMMENT, SEPARATOR)
	}
	sections := ListSections(COMMENT, SEPARATOR)
	for s := 0; s < len(sections); s++ {
		if sections[s] != "DEFAULT" {
			fmt.Printf("Create credentials for profile: " + sections[s] + "\n")
			config = ReadConfig(sections[s], COMMENT, SEPARATOR)
			if *passwordauth == true {
				if config.username == "None" || config.password == "None" {
					if username == "" || password == "" {
						username, password = GetCredentials()
						config.username = username
						config.password = password
					} else {
						config.username = username
						config.password = password
					}
				} else {
					username = config.username
					password = config.password
				}
			}
			saml, creds = AWSAuth(idpEndpoint, ADFS, USERAGENT, config.roleArn, config.principalArn, config.username, config.password, saml, passwordauth, DURATION)
			if creds != nil {
				WriteAWSConfigs(creds, config, sections[s], COMMENT, SEPARATOR)
			}
		}
	}
}
