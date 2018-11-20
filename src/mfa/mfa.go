package mfa


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
	"fmt"
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/parnurzeal/gorequest"
)


// MFA Bool if MFA is required
var MFA bool
// DEBUG Bool
var DEBUG bool

// IsMFA -- Does this connection require MFA? 
// Arguments:
//      body (string) 
//      resp (gorequest.Response) 
//      username (string) 
//      password (string) 
// Returns:
//      MFA (bool)
//      MFAStatus (string)
func IsMFA(body string, resp gorequest.Response, username string, password string) (bool, string) {
    // Form the payload
    MFA = false
    var pin string
    var Context string
    var MFAStatus string
    message := "For security reasons, we require additional information to verify your account"
    //Do we require MFA?
    if strings.Contains(body, message) {
        MFA = true
        fmt.Println("Please provide your MFA Token:")
        _, _ = fmt.Scanln(&pin)
        // Load up the response to parse
        doc, parseerror := goquery.NewDocumentFromReader(resp.Body)
        if parseerror != nil {
            fmt.Println(parseerror)
            if DEBUG {
                panic("Stack trace:")
            }
        }
        doc.Find("input[name=Context]").Each(func(i int, s *goquery.Selection) {
            context, exists := s.Attr("value")
            if exists {
                Context = context
            }
        })
        Status := url.Values{}
        Status.Set("security_code", pin)
        Status.Set("Continue", "Continue")
        Status.Set("AuthMethod", "VIPAuthenticationProviderWindowsAccountName")
        Status.Set("username", "")
        Status.Set("password", "")
        Status.Set("Context", Context)
        MFAStatus = Status.Encode()
    }
    return MFA, MFAStatus

}
