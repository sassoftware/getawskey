// +build windows,!linux,!darwin

package krb

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
	"fmt"
	"os"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/alexbrainman/sspi/ntlm"
	"github.com/parnurzeal/gorequest"
	"mfa"
)

// MFA Bool if MFA is required
var MFA bool
var mfaStatus string

// AuthKerb uses NTLM to pass your crendentials to ADFS and return your authorization in SAML for Windows.
func AuthKerb(idp string, ADFS string, USERAGENT string) (saml string) {
	request := gorequest.New()

	cred, err := ntlm.AcquireCurrentUserCredentials()
	if err != nil {
		fmt.Println("Unable to acquire kerberos TGT, please login as a domain user or use -pass for password prompt")
		fmt.Println(err)
		os.Exit(1)
	}
	defer cred.Release()

	secctx, negotiate, err := ntlm.NewClientContext(cred)
	if err != nil {
		panic(err)
	}
	defer secctx.Release()

	a, _, reqerror := request.Post(idp).
		Set("Accept-Encoding", "utf-8").
		Set("Accept", "*/*").
		Set("User-Agent", USERAGENT).
		Set("Authorization", "NTLM").
		End()
	if reqerror != nil {
		panic(reqerror)
	}
	redir := a.Request.URL.String()
	if a.Status != "401 Unauthorized" {
		fmt.Println("Something went wrong with ntlm auth. Are you logged in with a domain user?")
	}
	req, _, reqerror := request.Post(redir).
		Set("Accept-Encoding", "utf-8").
		Set("Accept", "*/*").
		Set("User-Agent", USERAGENT).
		Set("Authorization", "NTLM "+base64.StdEncoding.EncodeToString(negotiate)).
		End()
	if reqerror != nil {
		panic(reqerror)
	}
	authHeaders := req.Header.Get("Www-Authenticate")
	serverntlmresp := strings.Split(authHeaders, " ")[1]
	challenge, _ := base64.StdEncoding.DecodeString(serverntlmresp)
	authenticate, err := secctx.Update(challenge)
	if err != nil {
		panic(err)
	}
	f, fBody, reqerror := request.Post(redir).
		Set("Accept-Encoding", "utf-8").
		Set("Accept", "*/*").
		Set("User-Agent", USERAGENT).
		Set("Authorization", "NTLM "+base64.StdEncoding.EncodeToString(authenticate)).
		End()
	if reqerror != nil {
		panic(reqerror)
	}
	if MFA == false {
		MFA, mfaStatus = mfa.IsMFA(fBody, f, "", "")
	}
	if MFA {
		f, _, reqerror = request.Post(idp).
			Send(mfaStatus).
			Set("Accept-Encoding", "utf-8").
			Set("Accept", "*/*").
			Set("User-Agent", USERAGENT).
			Set("Authorization", "NTLM "+base64.StdEncoding.EncodeToString(authenticate)).
			End()
		if reqerror != nil {
			panic(reqerror)
		}
		redir := f.Request.URL.String()
		f, _, reqerror = request.Post(redir).
			Send(mfaStatus).
			Set("Accept-Encoding", "utf-8").
			Set("Accept", "*/*").
			Set("User-Agent", USERAGENT).
			Set("Authorization", "NTLM "+base64.StdEncoding.EncodeToString(authenticate)).
			End()
		if reqerror != nil {
			panic(reqerror)
		}
	}

	// Load up the response to parse
	doc, parseerror := goquery.NewDocumentFromReader(f.Body)
	if parseerror != nil {
		panic(parseerror)
	}
	samlout := ""
	// Find the saml response and return it
	doc.Find("input[name=SAMLResponse]").Each(func(i int, s *goquery.Selection) {
		saml, exists := s.Attr("value")
		if exists {
			samlout = saml
		}
	})

	return samlout
}
