## Tooling for AWS Authentication

**Archived project: This projet is no longer in active development and has been archived on 2024-07-22.**

### License

Copyright (c) 2017-2018 by SAS Institute Inc., Cary, NC 27513 USA

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the license at

   http://www.apache.org/licenses/LICENSE-2.0

The license is also included in this repository here:

   [LICENSE](LICENSE)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

### Getawskey
This is a simple go executable that will authenticate you against an ADFS cluster and retrieve temporary AWS credentials for one or many roles. 
It creates ~/.aws/config and ~/.aws/credentials files for the AWS cli commands and the Boto SDK used by most other scripts.
This is useful when your organizations uses SAML based federation using ADFS for access to your AWS accounts, and you wish to run API/CLI calls using this access.


Features: 

* Supports ADFS based MFA
* Authenticates using NTLM/Kerberos to avoid having to manually type your password, but also supports manually entering your username/password.
* Allows you to select a specific role, or connect to all roles to which you have access.  If you only have access to one role, it will automatially select that role.
* Supports Ubuntu/RHEL/OSX/Windows
    

For more details on setting up your AWS account to authenticate with your Active Directory, please see Amazon's documentation:

* https://aws.amazon.com/blogs/security/enabling-federation-to-aws-using-windows-active-directory-adfs-and-saml-2-0/


### Requirements
For Windows, you must be logged in with a domain user in order to authenticate with ntlm.

If you are running OSX/Linux, you may need up to date GSSAPI C dev packages in additional to the normal kerberos packages.

See upstream notes here: https://github.com/apcera/gssapi

Always install the latest Golang version for your OS:

    Install latest version of Golang: https://golang.org/dl/
    #Setup environment variables as needed for your Golang Env
    

OSX: 

Install Homebrew: http://brew.sh/

    $ brew install heimdal --without-x11
    Ensure you have a valid /etc/krb5.conf
    
Debian:

    $ apt-get install krb5-user libsasl2-modules-gssapi-mit libkrb5-dev 
    When prompted, set default realm as appropriate: example.company.com 

Rhel7/CentOS7:

    $ yum install krb5-libs krb5-devel krb5-workstation
    Ensure you have a valid /etc/krb5.conf

#### Usage:

#### Running binary 

For Linux/Darwin, ensure you have a Kerberos TGT: 

Usage of ./getawskey:

    -adfs string
    	Specify ADFS cluster FQDN (default "example.yourcompany.com")
    -createall
    	Writes a config with all role_arn's you have permissions to
    -debug
    	Print stack traces upon error and extra debugging information.
    -duration int
    	Specify Session Duration (Seconds) up to the amount specified on the role. Example: 43200 (default 3600)
    -file string
    	use an alternate config file (default "/home/ubuntu/.aws/awskeyconfig")
    -pass
      	Authenticate using interactive or saved username/password
    -prompt
    	Prompt with list of accounts like on first run and overwrites profile DEFAULT, createall takes priority
    -useragent string
    	Specify browser useragent compatible with your ADFS (default "MSIE 6.0; Windows NT")
    -version
    	Print version and exit
    
    getawskey 
    Creating /Users/MyUser/.aws/awskeyconfig....
    
    [ 0 ]:  arn:aws:iam::123456789123:role/admin
    [ 1 ]:  arn:aws:iam::123456789123:role/dev
    [ 2 ]:  arn:aws:iam::123456789123:role/devtest
    Please choose a role to assume:  2
    you selected: 2
    Assuming role:  arn:aws:iam::123456789123:role/devtest
    Create credentials for profile: default
    
    getawskey -pass
    Create credentials for profile: default
    Domain\Username: YourCompanyDomain\MyUser
    Password: 


#### Build instructions 
Currenty, there are 3 separate packages under the git repo:


     
Repo: repot/getawskey-go/

Package folders: getawskey, krb, mfa

To build on Linux/Darwin:

    Ensure you have the requirements listed above for your OS:
    export GOPATH=/path/to/opensource-getawskey
    Run "go get" for each listed dependency in requirements-linuxdarwin.txt
       for i in $(cat requirements-linuxdarwin.txt); do echo "$i"; go get "$i"; done
    Note, you can set a default ADFS cluster by editing the ADFS flag:  src/getawskey/getawskey.go
    Build go package: go build getawskey



To build on Windows:

    Ensure you have the requirements listed above for Windows
    export GOPATH=\path\to\opensource-getawskey
    Run "go get" for each listed dependency in requiresments-windows.txt
    Note, you can set a default ADFS cluster by editing the ADFS flag:  src/getawskey/getawskey.go
    Build go package: go build getawskey

    


### Support


### Links


### Release Notes
Version 0.1.4 Initial Release 
