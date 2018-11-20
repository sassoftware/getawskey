// +build !windows

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
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"
	"sync"

	"github.com/PuerkitoBio/goquery"
	"github.com/apcera/gssapi"
	"github.com/parnurzeal/gorequest"
	"mfa"
)

// Context struct is used by gssapi.
type Context struct {
	DebugLog    bool
	ServiceName string
	gssapi.Options
	*gssapi.Lib `json:"-"`
	loadonce    sync.Once
	credential  *gssapi.CredId `json:"-"`
}

// MFA Bool if MFA is required
var MFA bool
var mfaStatus string
var c = &Context{}

func loadlib(debug bool, prefix string) (*gssapi.Lib, error) {
	max := gssapi.Err + 1
	if debug {
		max = gssapi.MaxSeverity
	}
	pp := make([]gssapi.Printer, 0, max)
	for i := gssapi.Severity(0); i < max; i++ {
		p := log.New(os.Stderr,
			fmt.Sprintf("%s: %s\t", prefix, i),
			log.LstdFlags)
		pp = append(pp, p)
	}
	c.Options.Printers = pp

	lib, err := gssapi.Load(&c.Options)
	if err != nil {
		return nil, err
	}
	return lib, nil
}

func prepareServiceName() *gssapi.Name {
	if c.ServiceName == "" {
		panic("Need a service name")
	}
	nameBuf, err := c.MakeBufferString(c.ServiceName)
	if err != nil {
		panic(err)
	}
	defer nameBuf.Release()

	name, err := nameBuf.Name(c.GSS_KRB5_NT_PRINCIPAL_NAME)
	if err != nil {
		panic(err)
	}
	if name.String() != c.ServiceName {
		panic(fmt.Sprintf("name: got %q, expected %q", name.String(), c.ServiceName))
	}

	return name
}

// AuthKerb passes your kerberos TGT to ADFS and returns your authorization in saml format.
func AuthKerb(idp string, ADFS string, USERAGENT string) (saml string) {
	var bodyf func(*gssapi.CtxId) string
	//load headers
	c.DebugLog = false
	var maclibgssapi string
	var linuxlibgssapi string
	var libgssapi string
	var ubuntulibgssapi string
	maclibgssapi = "/usr/lib/sasl2/libgssapiv2.2.so"
	linuxlibgssapi = "/usr/lib64/libgssapi_krb5.so"
	ubuntulibgssapi = "/usr/lib/x86_64-linux-gnu/sasl2/libgssapiv2.so"

	if _, err := os.Stat(maclibgssapi); err == nil {
		libgssapi = maclibgssapi
	} else if _, err = os.Stat(linuxlibgssapi); err == nil {
		libgssapi = linuxlibgssapi
	} else if _, err = os.Stat(ubuntulibgssapi); err == nil {
		libgssapi = ubuntulibgssapi
	} else {
		fmt.Println("Requires header files to run")
		fmt.Println("See: https://github.com/apcera/gssapi")
		fmt.Println("expecting " + maclibgssapi + " or " + linuxlibgssapi)
		os.Exit(1)
	}
	c.Options.LibPath = libgssapi
	c.Options.Krb5Config = "/etc/krb5.conf"
	c.ServiceName = "HTTP/" + ADFS

	lib, err := loadlib(c.DebugLog, "go-gssapi-test")
	if err != nil {
		panic(err)
	}
	c.Lib = lib

	// establish a context
	ctx, _, token, _, _, err := c.InitSecContext(
		c.GSS_C_NO_CREDENTIAL,
		nil,
		prepareServiceName(),
		c.GSS_C_NO_OID,
		0,
		0,
		c.GSS_C_NO_CHANNEL_BINDINGS,
		c.GSS_C_NO_BUFFER)
	defer token.Release()
	if err != nil {
		e, ok := err.(*gssapi.Error)
		if ok && e.Major.ContinueNeeded() {
			panic("Unexpected GSS_S_CONTINUE_NEEDED")
		}
		fmt.Println("Unable to acquire kerberos TGT, please verify kerberos credentials or use -pass for password prompt")
		fmt.Println(err)
		os.Exit(1)
	}

	body := io.Reader(nil)
	if bodyf != nil {
		body = bytes.NewBufferString(bodyf(ctx))
	}

	v := "Negotiate"
	data := token.Bytes()
	v = v + " " + base64.StdEncoding.EncodeToString(data)

	// Send the request
	request := gorequest.New()
	r, _, reqerror := request.Post(idp).Send(body).
		Set("Accept-Encoding", "utf-8").
		Set("Accept", "*/*").
		Set("User-Agent", USERAGENT).
		Set("Authorization", "Negotiate").
		End()
	if reqerror != nil {
		panic(reqerror)
	}
	redir := r.Request.URL.String()
	if r.Status != "401 Unauthorized" {
		fmt.Println("Something went wrong with kerberos auth.  Verify you have a current ticket")
		os.Exit(1)
	}

	a, aBody, reqerror := request.Get(redir).Send(body).
		Set("Accept-Encoding", "utf-8").
		Set("Accept", "*/*").
		Set("User-Agent", USERAGENT).
		Set("Authorization", v).
		End()
	if reqerror != nil {
		panic(reqerror)
	}

	if MFA == false {
		MFA, mfaStatus = mfa.IsMFA(aBody, a, "", "")
	}
	if MFA {
		r, _, reqerror = request.
			Post(idp).
			Send(mfaStatus).
			Send(body).
			Set("Accept-Encoding", "utf-8").
			Set("Accept", "*/*").
			Set("User-Agent", USERAGENT).
			Set("Authorization", "Negotiate").
			End()
		redir := r.Request.URL.String()
		if reqerror != nil {
			panic(reqerror)
		}
		a, aBody, reqerror = request.Get(redir).
			Send(mfaStatus).
			Send(body).
			Set("Accept-Encoding", "utf-8").
			Set("Accept", "*/*").
			Set("User-Agent", USERAGENT).
			Set("Authorization", v).
			End()
		if reqerror != nil {
			panic(reqerror)
		}
	}

	// Load up the response to parse
	doc, parseerror := goquery.NewDocumentFromReader(a.Body)
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
	defer ctx.Release()
	return samlout
}
