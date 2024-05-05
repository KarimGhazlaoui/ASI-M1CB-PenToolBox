import csv
import json

def parse_csv_report(csv_data):
    scan_results = []
    # Split the CSV data into lines and remove any leading/trailing whitespace
    lines = csv_data.strip().split('\n')
    # Extract the header row and remove any leading/trailing whitespace
    header = lines[0].strip().split(',')
    # Parse the remaining rows using DictReader
    reader = csv.DictReader(lines[1:], fieldnames=header)
    for row in reader:
        scan_results.append({
            'IP': row.get('IP', ''),
            'Port': row.get('Port', ''),
            'Protocol': row.get('Port Protocol', ''),
            'Sévérité': row.get('Severity', ''),
            'NVT': row.get('NVT Name', ''),
            'CVE': row.get('CVEs', '')
        })
    return scan_results

# Example usage:
csv_data = """
IP,Hostname,Port,Port Protocol,CVSS,Severity,QoD,Solution Type,NVT Name,Summary,Specific Result,NVT OID,CVEs,Task ID,Task Name,Timestamp,Result ID,Impact,Solution,Affected Software/OS,Vulnerability Insight,Vulnerability Detection Method,Product Detection Result,BIDs,CERTs,Other References
192.168.1.29,,80,tcp,10.0,High,80,"VendorFix","TWiki XSS and Command Execution Vulnerabilities","TWiki is prone to Cross-Site Scripting (XSS) and Command Execution Vulnerabilities.","Installed version: 01.Feb.2003
Fixed version:     4.2.4

",1.3.6.1.4.1.25623.1.0.800320,"CVE-2008-5304,CVE-2008-5305",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,26c4c366-d5a6-4801-99fd-f3d317538fc8,"Successful exploitation could allow execution of arbitrary script code or
  commands. This could let attackers steal cookie-based authentication credentials or compromise the affected
  application.","Upgrade to version 4.2.4 or later.","TWiki, TWiki version prior to 4.2.4.","The flaws are due to:

  - %URLPARAM{}% variable is not properly sanitized which lets attackers
    conduct cross-site scripting attack.

  - %SEARCH{}% variable is not properly sanitised before being used in an
    eval() call which lets the attackers execute perl code through eval
    injection attack.","
Details:
TWiki XSS and Command Execution Vulnerabilities
(OID: 1.3.6.1.4.1.25623.1.0.800320)
Version used: 2024-03-01T14:37:10Z
","","","",""
192.168.1.29,,512,tcp,10.0,High,80,"Mitigation","The rexec service is running","This remote host is running a rexec service.","The rexec service was detected on the target system.
",1.3.6.1.4.1.25623.1.0.100111,"CVE-1999-0618",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,4bce561d-e0e3-48da-912f-e460ca83b6d7,"","Disable the rexec service and use alternatives like SSH
  instead.","","rexec (remote execution client for an exec server) has the same
  kind of functionality that rsh has: you can execute shell commands on a remote computer.

  The main difference is that rexec authenticate by reading the username and password *unencrypted*
  from the socket.","Checks whether an rexec service is exposed on the target
  host.
Details:
The rexec service is running
(OID: 1.3.6.1.4.1.25623.1.0.100111)
Version used: 2023-09-12T05:05:19Z
","","","",""
192.168.1.29,,,,10.0,High,80,"Mitigation","Operating System (OS) End of Life (EOL) Detection","The Operating System (OS) on the remote host has reached the end
  of life (EOL) and should not be used anymore.","The ""Ubuntu"" Operating System on the remote host has reached the end of life.

CPE:               cpe:/o:canonical:ubuntu_linux:8.04
Installed version,
build or SP:       8.04
EOL date:          2013-05-09
EOL info:          https://wiki.ubuntu.com/Releases
",1.3.6.1.4.1.25623.1.0.103674,"",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,31ddbf76-3ece-4653-9a13-68a7baf7b2af,"An EOL version of an OS is not receiving any security updates
  from the vendor. Unfixed security vulnerabilities might be leveraged by an attacker to compromise
  the security of this host.","Upgrade the OS on the remote host to a version which is still
  supported and receiving security updates by the vendor.","","","Checks if an EOL version of an OS is present on the target
  host.
Details:
Operating System (OS) End of Life (EOL) Detection
(OID: 1.3.6.1.4.1.25623.1.0.103674)
Version used: 2024-02-28T14:37:42Z
","Product: cpe:/o:canonical:ubuntu_linux:8.04
Method: OS Detection Consolidation and Reporting
(OID: 1.3.6.1.4.1.25623.1.0.105937)
","","",""
192.168.1.29,,1524,tcp,10.0,High,99,"Workaround","Possible Backdoor: Ingreslock","A backdoor is installed on the remote host.","The service is answering to an 'id;' command with the following response: uid=0(root) gid=0(root)
",1.3.6.1.4.1.25623.1.0.103549,"",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,1871009c-2631-44d9-868c-ff144a2e614a,"Attackers can exploit this issue to execute arbitrary commands in the
  context of the application. Successful attacks will compromise the affected isystem.","A whole cleanup of the infected system is recommended.","","","
Details:
Possible Backdoor: Ingreslock
(OID: 1.3.6.1.4.1.25623.1.0.103549)
Version used: 2023-07-25T05:05:58Z
","","","",""
192.168.1.29,,8787,tcp,10.0,High,99,"Mitigation","Distributed Ruby (dRuby/DRb) Multiple Remote Code Execution Vulnerabilities","Systems using Distributed Ruby (dRuby/DRb), which is available in Ruby versions 1.6
  and later, may permit unauthorized systems to execute distributed commands.","The service is running in $SAFE >= 1 mode. However it is still possible to run arbitrary syscall commands on the remote host. Sending an invalid syscall the service returned the following response:

Flo:Errno::ENOSYS:bt[""3/usr/lib/ruby/1.8/drb/drb.rb:1555:in `syscall'""0/usr/lib/ruby/1.8/drb/drb.rb:1555:in `send'""4/usr/lib/ruby/1.8/drb/drb.rb:1555:in `__send__'""A/usr/lib/ruby/1.8/drb/drb.rb:1555:in `perform_without_block'""3/usr/lib/ruby/1.8/drb/drb.rb:1515:in `perform'""5/usr/lib/ruby/1.8/drb/drb.rb:1589:in `main_loop'""0/usr/lib/ruby/1.8/drb/drb.rb:1585:in `loop'""5/usr/lib/ruby/1.8/drb/drb.rb:1585:in `main_loop'""1/usr/lib/ruby/1.8/drb/drb.rb:1581:in `start'""5/usr/lib/ruby/1.8/drb/drb.rb:1581:in `main_loop'""//usr/lib/ruby/1.8/drb/drb.rb:1430:in `run'""1/usr/lib/ruby/1.8/drb/drb.rb:1427:in `start'""//usr/lib/ruby/1.8/drb/drb.rb:1427:in `run'""6/usr/lib/ruby/1.8/drb/drb.rb:1347:in `initialize'""//usr/lib/ruby/1.8/drb/drb.rb:1627:in `new'""9/usr/lib/ruby/1.8/drb/drb.rb:1627:in `start_service'""%/usr/sbin/druby_timeserver.rb:12:errnoi+:mesg""Function not implemented
",1.3.6.1.4.1.25623.1.0.108010,"",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,90e77b06-5011-4e54-b047-a1bd88f4375b,"By default, Distributed Ruby does not impose restrictions on allowed hosts or set the
  $SAFE environment variable to prevent privileged activities. If other controls are not in place, especially if the
  Distributed Ruby process runs with elevated privileges, an attacker could execute arbitrary system commands or Ruby
  scripts on the Distributed Ruby server. An attacker may need to know only the URI of the listening Distributed Ruby
  server to submit Ruby commands.","Administrators of environments that rely on Distributed Ruby should ensure that
  appropriate controls are in place. Code-level controls may include:

  - Implementing taint on untrusted input

  - Setting $SAFE levels appropriately (>=2 is recommended if untrusted hosts are allowed to submit Ruby commands, and >=3 may be appropriate)

  - Including drb/acl.rb to set ACLEntry to restrict access to trusted hosts","","","Send a crafted command to the service and check for a remote command execution
  via the instance_eval or syscall requests.
Details:
Distributed Ruby (dRuby/DRb) Multiple Remote Code Execution Vulnerabilities
(OID: 1.3.6.1.4.1.25623.1.0.108010)
Version used: 2023-07-20T05:05:17Z
","","","",""
192.168.1.29,,21,tcp,9.8,High,99,"VendorFix","vsftpd Compromised Source Packages Backdoor Vulnerability","vsftpd is prone to a backdoor vulnerability.","Vulnerability was detected according to the Vulnerability Detection Method.",1.3.6.1.4.1.25623.1.0.103185,"CVE-2011-2523",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,6ced0e00-dcf8-45e2-b7db-971fc6f5061b,"Attackers can exploit this issue to execute arbitrary commands in
  the context of the application. Successful attacks will compromise the affected application.","The repaired package can be downloaded from the referenced
  vendor homepage. Please validate the package with its signature.","The vsftpd 2.3.4 source package downloaded between 20110630 and
  20110703 is affected.","The tainted source package contains a backdoor which opens a
  shell on port 6200/tcp.","
Details:
vsftpd Compromised Source Packages Backdoor Vulnerability
(OID: 1.3.6.1.4.1.25623.1.0.103185)
Version used: 2023-12-07T05:05:41Z
","Product: cpe:/a:beasts:vsftpd:2.3.4
Method: vsFTPd FTP Server Detection
(OID: 1.3.6.1.4.1.25623.1.0.111050)
","","",""
192.168.1.29,,8009,tcp,9.8,High,99,"VendorFix","Apache Tomcat AJP RCE Vulnerability (Ghostcat)","Apache Tomcat is prone to a remote code execution vulnerability
  (dubbed 'Ghostcat') in the AJP connector.","It was possible to read the file ""/WEB-INF/web.xml"" through the AJP connector.

Result:

AB 8\x0004 Ã\x0088 \x0002OK  \x0001 \x000CContent-Type  \x001Ctext/html;charset=ISO-8859-1 AB\x001FÃ¼\x0003\x001FÃ¸<!--
  Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to You under the Apache License, Version 2.0
  (the ""License""); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an ""AS IS"" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->
<?xml version=""1.0"" encoding=""ISO-8859-1""?>
<!DOCTYPE html PUBLIC ""-//W3C//DTD XHTML 1.0 Strict//EN""
   ""http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"">

<html xmlns=""http://www.w3.org/1999/xhtml"" xml:lang=""en"" lang=""en"">
    <head>
    <title>Apache Tomcat/5.5</title>
    <style type=""text/css"">
    /*<![CDATA[*/
      body {
          color: #000000;
          background-color: #FFFFFF;
	  font-family: Arial, ""Times New Roman"", Times, serif;
          margin: 10px 0px;
      }

    img {
       border: none;
    }
    
    a:link, a:visited {
        color: blue
    }

    th {
        font-family: Verdana, ""Times New Roman"", Times, serif;
        font-size: 110%;
        font-weight: normal;
        font-style: italic;
        background: #D2A41C;
        text-align: left;
    }

    td {
        color: #000000;
	font-family: Arial, Helvetica, sans-serif;
    }
    
    td.menu {
        background: #FFDC75;
    }

    .center {
        text-align: center;
    }

    .code {
        color: #000000;
        font-family: ""Courier New"", Courier, monospace;
        font-size: 110%;
        margin-left: 2.5em;
    }
    
     #banner {
        margin-bottom: 12px;
     }

     p#congrats {
         margin-top: 0;
         font-weight: bold;
         text-align: center;
     }

     p#footer {
         text-align: right;
         font-size: 80%;
     }
     /*]]>*/
   </style>
</head>

<body>

<!-- Header -->
<table id=""banner"" width=""100%"">
    <tr>
      <td align=""left"" style=""width:130px"">
        <a href=""http://tomcat.apache.org/"">
	  <img src=""tomcat.gif"" height=""92"" width=""130"" alt=""The Mighty Tomcat - MEOW!""/>
	</a>
      </td>
      <td align=""left"" valign=""top""><b>Apache Tomcat/5.5</b></td>
      <td align=""right"">
        <a href=""http://www.apache.org/"">
	  <img src=""asf-logo-wide.gif"" height=""51"" width=""537"" alt=""The Apache Software Foundation""/>
	</a>
       </td>
     </tr>
</table>

<table>
    <tr>

        <!-- Table of Contents -->
        <td valign=""top"">
            <table width=""100%"" border=""1"" cellspacing=""0"" cellpadding=""3"">
                <tr>
		  <th>Administration</th>
                </tr>
                <tr>
		  <td class=""menu"">
		    <a href=""manager/status"">Status</a><br/>
                    <a href=""admin"">Tomcat&nbsp;Administration</a><br/>
                    <a href=""manager/html"">Tomcat&nbsp;Manager</a><br/>
                    &nbsp;
                  </td>
                </tr>
            </table>

	    <br />
            <table width=""100%"" border=""1"" cellspacing=""0"" cellpadding=""3"">
                <tr>
		  <th>Documentation</th>
                </tr>
                <tr>
                  <td class=""menu"">
                    <a href=""RELEASE-NOTES.txt"">Release&nbsp;Notes</a><br/>
                    <a href=""tomcat-docs/changelog.html"">Change&nbsp;Log</a><br/>
                    <a href=""tomcat-docs"">Tomcat&nbsp;Documentation</a><br/>                        &nbsp;
                    &nbsp;
		    </td>
                </tr>
            </table>
	    
            <br/>
            <table width=""100%"" border=""1"" cellspacing=""0"" cellpadding=""3"">
                <tr>
                  <th>Tomcat Online</th>
                </tr>
                <tr>
                  <td class=""menu"">
                    <a href=""http://tomcat.apache.org/"">Home&nbsp;Page</a><br/>
		    <a href=""http://tomcat.apache.org/faq/"">FAQ</a><br/>
                    <a href=""http://tomcat.apache.org/bugreport.html"">Bug&nbsp;Database</a><br/>
                    <a href=""http://issues.apache.org/bugzilla/buglist.cgi?bug_status=UNCONFIRMED&amp;bug_status=NEW&amp;bug_status=ASSIGNED&amp;bug_status=REOPENED&amp;bug_status=RESOLVED&amp;resolution=LATER&amp;resolution=REMIND&amp;resolution=---&amp;bugidtype=include&amp;product=Tomcat+5&amp;cmdtype=doit&amp;order=Importance"">Open Bugs</a><br/>
                    <a href=""http://mail-archives.apache.org/mod_mbox/tomcat-users/"">Users&nbsp;Mailing&nbsp;List</a><br/>
                    <a href=""http://mail-archives.apache.org/mod_mbox/tomcat-dev/"">Developers&nbsp;Mailing&nbsp;List</a><br/>
                    <a href=""irc://irc.freenode.net/#tomcat"">IRC</a><br/>
		    &nbsp;
                  </td>
                </tr>
            </table>
	    
            <br/>
            <table width=""100%"" border=""1"" cellspacing=""0"" cellpadding=""3"">
                <tr>
                  <th>Examples</th>
                </tr>
                <tr>
                  <td class=""menu"">
                    <a href=""jsp-examples/"">JSP&nbsp;Examples</a><br/>
                    <a href=""servlets-examples/"">Servlet&nbsp;Examples</a><br/>
                    <a href=""webdav/"">WebDAV&nbsp;capabilities</a><br/>
     		    &nbsp;
                  </td>
                </tr>
            </table>
	    
            <br/>
            <table width=""100%"" border=""1"" cellspacing=""0"" cellpadding=""3"">
                <tr>
		  <th>Miscellaneous</th>
                </tr>
                <tr>
                  <td class=""menu"">
                    <a href=""http://java.sun.com/products/jsp"">Sun's&nbsp;Java&nbsp;Server&nbsp;Pages&nbsp;Site</a><br/>
                    <a href=""http://java.sun.com/products/servlet"">Sun's&nbsp;Servlet&nbsp;Site</a><br/>
    		    &nbsp;
                  </td>
                </tr>
            </table>
        </td>

        <td style=""width:20px"">&nbsp;</td>
	
        <!-- Body -->
        <td align=""left"" valign=""top"">
          <p id=""congrats"">If you're seeing this page via a web browser, it means you've setup Tomcat successfully. Congratulations!</p>
 
          <p>As you may have guessed by now, this is the default Tomcat home page. It can be found on the local filesystem at:</p>
          <p class=""code"">$CATALINA_HOME/webapps/ROOT/index.jsp</p>
	  
          <p>where ""$CATALINA_HOME"" is the root of the Tomcat installation directory. If you're seeing this page, and you don't think you should be, then either you're either a user who has arrived at new installation of Tomcat, or you're an administrator who hasn't got his/her setup quite right. Providing the latter is the case, please refer to the <a href=""tomcat-docs"">Tomcat Documentation</a> for more detailed setup and administration information than is found in the INSTALL file.</p>

            <p><b>NOTE:</b> This page is precompiled. If you change it, this page will not change since
                  it was compiled into a servlet at build time.
                  (See <tt>$CATALINA_HOME/webapps/ROOT/WEB-INF/web.xml</tt> as to how it was mapped.)
            </p>

            <p><b>NOTE: For security reasons, using the administration webapp
            is restricted to users with role ""admin"". The manager webapp
            is restricted to users with role ""manager"".</b>
            Users are defined in <code>$CATALINA_HOME/conf/tomcat-users.xml</code>.</p>

            <p>Included with this release are a host of sample Servlets and JSPs (with associated source code), extensive documentation (including the Servlet 2.4 and JSP 2.0 API JavaDoc), and an introductory guide to developing web applications.</p>

            <p>Tomcat mailing lists are available at the Tomcat project web site:</p>

           <ul>
               <li><b><a href=""mailto:users@tomcat.apache.org"">users@tomc
",1.3.6.1.4.1.25623.1.0.143545,"CVE-2020-1938",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,bdbe1853-5ddc-4821-a305-aaa39f8141e8,"","Update Apache Tomcat to version 7.0.100, 8.5.51, 9.0.31 or later. For other products
  using Tomcat please contact the vendor for more information on fixed versions.","Apache Tomcat versions prior 7.0.100, 8.5.51 or 9.0.31 when the AJP connector
  is enabled.

  Other products like JBoss or Wildfly which are using Tomcat might be affected as well.","Apache Tomcat server has a file containing vulnerability, which can be used by
  an attacker to read or include any files in all webapp directories on Tomcat, such as webapp configuration files
  or source code.","Sends a crafted AJP request and checks the response.
Details:
Apache Tomcat AJP RCE Vulnerability (Ghostcat)
(OID: 1.3.6.1.4.1.25623.1.0.143545)
Version used: 2023-07-06T05:05:36Z
","","","DFN-CERT-2021-1736,DFN-CERT-2020-1508,DFN-CERT-2020-1413,DFN-CERT-2020-1276,DFN-CERT-2020-1134,DFN-CERT-2020-0850,DFN-CERT-2020-0835,DFN-CERT-2020-0821,DFN-CERT-2020-0569,DFN-CERT-2020-0557,DFN-CERT-2020-0501,DFN-CERT-2020-0381,WID-SEC-2024-0528,WID-SEC-2023-2480,CB-K20/0711,CB-K20/0705,CB-K20/0693,CB-K20/0555,CB-K20/0543,CB-K20/0154",""
192.168.1.29,,3306,tcp,9.8,High,95,"Mitigation","MySQL / MariaDB Default Credentials (MySQL Protocol)","It was possible to login into the remote MySQL as
  root using weak credentials.","It was possible to login as root with an empty password.


",1.3.6.1.4.1.25623.1.0.103551,"CVE-2001-0645,CVE-2004-2357,CVE-2006-1451,CVE-2007-2554,CVE-2007-6081,CVE-2009-0919,CVE-2014-3419,CVE-2015-4669,CVE-2016-6531,CVE-2018-15719",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,4580b739-39fa-4b1d-bf2a-c07604f64117,"","'- Change the password as soon as possible

  - Contact the vendor for other possible fixes / updates","The following products are know to use such weak credentials:

  - CVE-2001-0645: Symantec/AXENT NetProwler 3.5.x

  - CVE-2004-2357: Proofpoint Protection Server

  - CVE-2006-1451: MySQL Manager in Apple Mac OS X 10.3.9 and 10.4.6

  - CVE-2007-2554: Associated Press (AP) Newspower 4.0.1 and earlier

  - CVE-2007-6081: AdventNet EventLog Analyzer build 4030

  - CVE-2009-0919: XAMPP

  - CVE-2014-3419: Infoblox NetMRI before 6.8.5

  - CVE-2015-4669: Xsuite 2.x

  - CVE-2016-6531, CVE-2018-15719: Open Dental before version 18.4

  Other products might be affected as well.","","
Details:
MySQL / MariaDB Default Credentials (MySQL Protocol)
(OID: 1.3.6.1.4.1.25623.1.0.103551)
Version used: 2023-11-02T05:05:26Z
","Product: cpe:/a:mysql:mysql:5.0.51a
Method: MariaDB / Oracle MySQL Detection (MySQL Protocol)
(OID: 1.3.6.1.4.1.25623.1.0.100152)
","","",""
192.168.1.29,,6200,tcp,9.8,High,99,"VendorFix","vsftpd Compromised Source Packages Backdoor Vulnerability","vsftpd is prone to a backdoor vulnerability.","Vulnerability was detected according to the Vulnerability Detection Method.",1.3.6.1.4.1.25623.1.0.103185,"CVE-2011-2523",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,6cfef2af-bc61-4627-908f-a1b94afba59b,"Attackers can exploit this issue to execute arbitrary commands in
  the context of the application. Successful attacks will compromise the affected application.","The repaired package can be downloaded from the referenced
  vendor homepage. Please validate the package with its signature.","The vsftpd 2.3.4 source package downloaded between 20110630 and
  20110703 is affected.","The tainted source package contains a backdoor which opens a
  shell on port 6200/tcp.","
Details:
vsftpd Compromised Source Packages Backdoor Vulnerability
(OID: 1.3.6.1.4.1.25623.1.0.103185)
Version used: 2023-12-07T05:05:41Z
","","","",""
192.168.1.29,,3632,tcp,9.3,High,99,"VendorFix","DistCC RCE Vulnerability (CVE-2004-2687)","DistCC is prone to a remote code execution (RCE)
  vulnerability.","It was possible to execute the ""id"" command.

Result: uid=1(daemon) gid=1(daemon)
",1.3.6.1.4.1.25623.1.0.103553,"CVE-2004-2687",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,f9364609-8f60-420c-9436-da2769974227,"DistCC by default trusts its clients completely that in turn
  could allow a malicious client to execute arbitrary commands on the server.","Vendor updates are available. Please see the references for
  more information.

  For more information about DistCC's security see the references.","","DistCC 2.x, as used in XCode 1.5 and others, when not configured
  to restrict access to the server port, allows remote attackers to execute arbitrary commands via
  compilation jobs, which are executed by the server without authorization checks.","
Details:
DistCC RCE Vulnerability (CVE-2004-2687)
(OID: 1.3.6.1.4.1.25623.1.0.103553)
Version used: 2022-07-07T10:16:06Z
","","","DFN-CERT-2019-0381",""
192.168.1.29,,5900,tcp,9.0,High,95,"Mitigation","VNC Brute Force Login","Try to log in with given passwords via VNC protocol.","It was possible to connect to the VNC server with the password: password
",1.3.6.1.4.1.25623.1.0.106056,"",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,c26886da-f371-4788-babc-7722491ba156,"","Change the password to something hard to guess or enable
  password protection at all.","","This script tries to authenticate to a VNC server with the
  passwords set in the password preference. It will also test and report if no authentication /
  password is required at all.

  Note: Some VNC servers have a blacklisting scheme that blocks IP addresses after five unsuccessful
  connection attempts for a period of time. The script will abort the brute force attack if it
  encounters that it gets blocked.

  Note as well that passwords can be max. 8 characters long.","
Details:
VNC Brute Force Login
(OID: 1.3.6.1.4.1.25623.1.0.106056)
Version used: 2021-07-23T07:56:26Z
","","","",""
192.168.1.29,,5432,tcp,9.0,High,99,"Mitigation","PostgreSQL Default Credentials (PostgreSQL Protocol)","It was possible to login into the remote PostgreSQL as user
  postgres using weak credentials.","It was possible to login as user postgres with password ""postgres"".


",1.3.6.1.4.1.25623.1.0.103552,"",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,daa42269-75a5-4299-be1d-a3edddf4860f,"","Change the password as soon as possible.","","","
Details:
PostgreSQL Default Credentials (PostgreSQL Protocol)
(OID: 1.3.6.1.4.1.25623.1.0.103552)
Version used: 2023-07-25T05:05:58Z
","Product: cpe:/a:postgresql:postgresql:8.3.1
Method: PostgreSQL Detection (TCP)
(OID: 1.3.6.1.4.1.25623.1.0.100151)
","","",""
192.168.1.29,,6697,tcp,8.1,High,80,"VendorFix","UnrealIRCd Authentication Spoofing Vulnerability","UnrealIRCd is prone to authentication spoofing vulnerability.","Installed version: 3.2.8.1
Fixed version:     3.2.10.7

",1.3.6.1.4.1.25623.1.0.809883,"CVE-2016-7144",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,914544f7-a6ec-458f-bf57-d962eed7ce94,"Successful exploitation of this vulnerability
  will allows remote attackers to spoof certificate fingerprints and consequently
  log in as another user.","Upgrade to UnrealIRCd 3.2.10.7,
  or 4.0.6, or later.","UnrealIRCd before 3.2.10.7 and
  4.x before 4.0.6.","The flaw exists due to an error in
  the 'm_authenticate' function in 'modules/m_sasl.c' script.","Checks if a vulnerable version is present on the target host.
Details:
UnrealIRCd Authentication Spoofing Vulnerability
(OID: 1.3.6.1.4.1.25623.1.0.809883)
Version used: 2023-07-14T16:09:27Z
","Product: cpe:/a:unrealircd:unrealircd:3.2.8.1
Method: UnrealIRCd Detection
(OID: 1.3.6.1.4.1.25623.1.0.809884)
","","",""
192.168.1.29,,80,tcp,7.5,High,99,"Mitigation","Test HTTP dangerous methods","Misconfigured web servers allows remote clients to perform
  dangerous HTTP methods such as PUT and DELETE.","We could upload the following files via the PUT method at this web server:

http://192.168.1.29/dav/puttest1781522772.html

We could delete the following files via the DELETE method at this web server:

http://192.168.1.29/dav/puttest1781522772.html


",1.3.6.1.4.1.25623.1.0.10498,"",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,e9aacc8d-e248-435b-83e9-e65697341737,"'- Enabled PUT method: This might allow an attacker to upload
  and run arbitrary code on this web server.

  - Enabled DELETE method: This might allow an attacker to delete additional files on this web
  server.","Use access restrictions to these dangerous HTTP methods
  or disable them completely.","Web servers with enabled PUT and/or DELETE methods.","","Checks if dangerous HTTP methods such as PUT and DELETE are
  enabled and can be misused to upload or delete files.
Details:
Test HTTP dangerous methods
(OID: 1.3.6.1.4.1.25623.1.0.10498)
Version used: 2023-08-01T13:29:10Z
","","","",""
192.168.1.29,,6697,tcp,7.5,High,70,"VendorFix","UnrealIRCd Backdoor","Detection of backdoor in UnrealIRCd.","Vulnerability was detected according to the Vulnerability Detection Method.",1.3.6.1.4.1.25623.1.0.80111,"CVE-2010-2075",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,5a0bb64a-dcee-4c73-89a5-da9d6498616f,"","Install latest version of unrealircd and check signatures of
  software you're installing.","The issue affects Unreal 3.2.8.1 for Linux. Reportedly package
  Unreal3.2.8.1.tar.gz downloaded in November 2009 and later is affected. The MD5 sum of the
  affected file is 752e46f2d873c1679fa99de3f52a274d. Files with MD5 sum of
  7b741e94e867c0a7370553fd01506c66 are not affected.","Remote attackers can exploit this issue to execute arbitrary
  system commands within the context of the affected application.","
Details:
UnrealIRCd Backdoor
(OID: 1.3.6.1.4.1.25623.1.0.80111)
Version used: 2023-08-01T13:29:10Z
","","","",""
192.168.1.29,,2121,tcp,7.5,High,95,"Mitigation","FTP Brute Force Logins Reporting","It was possible to login into the remote FTP server using
  weak/known credentials.","It was possible to login with the following credentials <User>:<Password>

user:user
",1.3.6.1.4.1.25623.1.0.108718,"CVE-1999-0501,CVE-1999-0502,CVE-1999-0507,CVE-1999-0508,CVE-2001-1594,CVE-2013-7404,CVE-2017-8218,CVE-2018-19063,CVE-2018-19064",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,82632918-93d5-48b9-9752-745bcfbac1d6,"This issue may be exploited by a remote attacker to e.g. gain
  access to sensitive information or modify system configuration.","Change the password as soon as possible.","","The following devices are / software is known to be affected:

  - CVE-2001-1594: Codonics printer FTP service as used in GE Healthcare eNTEGRA P&R

  - CVE-2013-7404: GE Healthcare Discovery NM 750b

  - CVE-2017-8218: vsftpd on TP-Link C2 and C20i devices

  - CVE-2018-19063, CVE-2018-19064: Foscam C2 and Opticam i5 devices

  Note: As the VT 'FTP Brute Force Logins' (OID: 1.3.6.1.4.1.25623.1.0.108717) might run into a
  timeout the actual reporting of this vulnerability takes place in this VT instead.","Reports weak/known credentials detected by the VT
  'FTP Brute Force Logins' (OID: 1.3.6.1.4.1.25623.1.0.108717).
Details:
FTP Brute Force Logins Reporting
(OID: 1.3.6.1.4.1.25623.1.0.108718)
Version used: 2023-12-06T06:06:11+02:00
","","","",""
192.168.1.29,,80,tcp,7.5,High,95,"VendorFix","PHP-CGI-based setups vulnerability when parsing query string parameters from php files.","PHP is prone to an information-disclosure vulnerability.","By doing the following HTTP POST request:

""HTTP POST"" body : <?php phpinfo();?>
URL              : http://192.168.1.29/cgi-bin/php?%2D%64+%61%6C%6C%6F%77%5F%75%72%6C%5F%69%6E%63%6C%75%64%65%3D%6F%6E+%2D%64+%73%61%66%65%5F%6D%6F%64%65%3D%6F%66%66+%2D%64+%73%75%68%6F%73%69%6E%2E%73%69%6D%75%6C%61%74%69%6F%6E%3D%6F%6E+%2D%64+%64%69%73%61%62%6C%65%5F%66%75%6E%63%74%69%6F%6E%73%3D%22%22+%2D%64+%6F%70%65%6E%5F%62%61%73%65%64%69%72%3D%6E%6F%6E%65+%2D%64+%61%75%74%6F%5F%70%72%65%70%65%6E%64%5F%66%69%6C%65%3D%70%68%70%3A%2F%2F%69%6E%70%75%74+%2D%64+%63%67%69%2E%66%6F%72%63%65%5F%72%65%64%69%72%65%63%74%3D%30+%2D%64+%63%67%69%2E%72%65%64%69%72%65%63%74%5F%73%74%61%74%75%73%5F%65%6E%76%3D%30+%2D%6E

it was possible to execute the ""<?php phpinfo();?>"" command.

Result: <title>phpinfo()</title><meta name=""ROBOTS"" content=""NOINDEX,NOFOLLOW,NOARCHIVE"" /></head>
",1.3.6.1.4.1.25623.1.0.103482,"CVE-2012-1823,CVE-2012-2311,CVE-2012-2336,CVE-2012-2335",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,5b2106cb-7821-4bde-8fcf-c8b2d9f9caa7,"Exploiting this issue allows remote attackers to view the source code of files in the
  context of the server process. This may allow the attacker to obtain sensitive information and to run arbitrary PHP code
  on the affected computer. Other attacks are also possible.","PHP has released version 5.4.3 and 5.3.13 to address this vulnerability.
  PHP is recommending that users upgrade to the latest version of PHP.","","When PHP is used in a CGI-based setup (such as Apache's mod_cgid), the
  php-cgi receives a processed query string parameter as command line arguments which allows command-line
  switches, such as -s, -d or -c to be passed to the php-cgi binary, which can be exploited to disclose
  source code and obtain arbitrary code execution.

  An example of the -s command, allowing an attacker to view the source code of index.php is below:

  http://example.com/index.php?-s","Sends a crafted HTTP POST request and checks the response.
Details:
PHP-CGI-based setups vulnerability when parsing query string parameters from...
(OID: 1.3.6.1.4.1.25623.1.0.103482)
Version used: 2022-08-09T10:11:17Z
","","","DFN-CERT-2013-1494,DFN-CERT-2012-1316,DFN-CERT-2012-1276,DFN-CERT-2012-1268,DFN-CERT-2012-1267,DFN-CERT-2012-1266,DFN-CERT-2012-1173,DFN-CERT-2012-1101,DFN-CERT-2012-0994,DFN-CERT-2012-0993,DFN-CERT-2012-0992,DFN-CERT-2012-0920,DFN-CERT-2012-0915,DFN-CERT-2012-0914,DFN-CERT-2012-0913,DFN-CERT-2012-0907,DFN-CERT-2012-0906,DFN-CERT-2012-0900,DFN-CERT-2012-0880,DFN-CERT-2012-0878",""
192.168.1.29,,5432,tcp,7.4,High,70,"VendorFix","SSL/TLS: OpenSSL CCS Man in the Middle Security Bypass Vulnerability","OpenSSL is prone to security-bypass vulnerability.","Vulnerability was detected according to the Vulnerability Detection Method.",1.3.6.1.4.1.25623.1.0.105042,"CVE-2014-0224",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,7c3738cd-5bc0-4ee2-a51d-25bddc860f20,"Successfully exploiting this issue may allow attackers to obtain
  sensitive information by conducting a man-in-the-middle attack. This may lead to other attacks.","Updates are available. Please see the references for more information.","OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m and 1.0.1 before 1.0.1h.","OpenSSL does not properly restrict processing of ChangeCipherSpec
  messages, which allows man-in-the-middle attackers to trigger use of a zero-length master key in
  certain OpenSSL-to-OpenSSL communications, and consequently hijack sessions or obtain sensitive
  information, via a crafted TLS handshake, aka the 'CCS Injection' vulnerability.","Send two SSL ChangeCipherSpec request and check the response.
Details:
SSL/TLS: OpenSSL CCS Man in the Middle Security Bypass Vulnerability
(OID: 1.3.6.1.4.1.25623.1.0.105042)
Version used: 2023-07-26T05:05:09Z
","","","DFN-CERT-2016-0388,DFN-CERT-2015-0593,DFN-CERT-2015-0427,DFN-CERT-2015-0396,DFN-CERT-2015-0082,DFN-CERT-2015-0079,DFN-CERT-2015-0078,DFN-CERT-2014-1717,DFN-CERT-2014-1632,DFN-CERT-2014-1364,DFN-CERT-2014-1357,DFN-CERT-2014-1350,DFN-CERT-2014-1265,DFN-CERT-2014-1209,DFN-CERT-2014-0917,DFN-CERT-2014-0789,DFN-CERT-2014-0778,DFN-CERT-2014-0768,DFN-CERT-2014-0752,DFN-CERT-2014-0747,DFN-CERT-2014-0738,DFN-CERT-2014-0715,DFN-CERT-2014-0714,DFN-CERT-2014-0709,WID-SEC-2023-0500,CB-K15/0567,CB-K15/0415,CB-K15/0384,CB-K15/0080,CB-K15/0079,CB-K15/0074,CB-K14/1617,CB-K14/1537,CB-K14/1299,CB-K14/1297,CB-K14/1294,CB-K14/1202,CB-K14/1174,CB-K14/1153,CB-K14/0876,CB-K14/0756,CB-K14/0746,CB-K14/0736,CB-K14/0722,CB-K14/0716,CB-K14/0708,CB-K14/0684,CB-K14/0683,CB-K14/0680",""
192.168.1.29,,25,tcp,6.8,Medium,99,"VendorFix","Multiple Vendors STARTTLS Implementation Plaintext Arbitrary Command Injection Vulnerability","Multiple vendors' implementations of 'STARTTLS' are prone to a
  vulnerability that lets attackers inject arbitrary commands.","Vulnerability was detected according to the Vulnerability Detection Method.",1.3.6.1.4.1.25623.1.0.103935,"CVE-2011-0411,CVE-2011-1430,CVE-2011-1431,CVE-2011-1432,CVE-2011-1506,CVE-2011-1575,CVE-2011-1926,CVE-2011-2165",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,8ff5be99-f14d-4fa2-b999-3887bcfe706f,"An attacker can exploit this issue to execute arbitrary commands
  in the context of the user running the application. Successful exploits can allow attackers to
  obtain email usernames and passwords.","Updates are available. Please see the references for more
  information.","The following vendors are known to be affected:

  Ipswitch

  Kerio

  Postfix

  Qmail-TLS

  Oracle

  SCO Group

  spamdyke

  ISC","","Send a special crafted 'STARTTLS' request and check the
  response.
Details:
Multiple Vendors STARTTLS Implementation Plaintext Arbitrary Command Injecti...
(OID: 1.3.6.1.4.1.25623.1.0.103935)
Version used: 2023-10-31T05:06:37Z
","","","DFN-CERT-2011-0917,DFN-CERT-2011-0912,DFN-CERT-2011-0897,DFN-CERT-2011-0844,DFN-CERT-2011-0818,DFN-CERT-2011-0808,DFN-CERT-2011-0771,DFN-CERT-2011-0741,DFN-CERT-2011-0712,DFN-CERT-2011-0673,DFN-CERT-2011-0597,DFN-CERT-2011-0596,DFN-CERT-2011-0519,DFN-CERT-2011-0516,DFN-CERT-2011-0483,DFN-CERT-2011-0434,DFN-CERT-2011-0393,DFN-CERT-2011-0381,CB-K15/1514",""
192.168.1.29,,80,tcp,6.8,Medium,80,"VendorFix","TWiki Cross-Site Request Forgery Vulnerability (Sep 2010)","TWiki is prone to a cross-site request forgery (CSRF) vulnerability.","Installed version: 01.Feb.2003
Fixed version:     4.3.2

",1.3.6.1.4.1.25623.1.0.801281,"CVE-2009-4898",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,dd968d21-c900-44a4-945e-824ae3716f7d,"Successful exploitation will allow attacker to gain administrative
  privileges on the target application and can cause CSRF attack.","Upgrade to TWiki version 4.3.2 or later.","TWiki version prior to 4.3.2","Attack can be done by tricking an authenticated TWiki user into visiting
  a static HTML page on another side, where a Javascript enabled browser will send an HTTP POST request
  to TWiki, which in turn will process the request as the TWiki user.","
Details:
TWiki Cross-Site Request Forgery Vulnerability (Sep 2010)
(OID: 1.3.6.1.4.1.25623.1.0.801281)
Version used: 2024-03-01T14:37:10Z
","","","",""
192.168.1.29,,21,tcp,6.4,Medium,80,"Mitigation","Anonymous FTP Login Reporting","Reports if the remote FTP Server allows anonymous logins.","It was possible to login to the remote FTP service with the following anonymous account(s):

anonymous:anonymous@example.com
ftp:anonymous@example.com

",1.3.6.1.4.1.25623.1.0.900600,"CVE-1999-0497",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,855f2c42-ce7d-4659-826a-d9e0fd759630,"Based on the files accessible via this anonymous FTP login and
  the permissions of this account an attacker might be able to:

  - gain access to sensitive files

  - upload or delete files.","If you do not want to share files, you should disable anonymous
  logins.","","A host that provides an FTP service may additionally provide
  Anonymous FTP access as well. Under this arrangement, users do not strictly need an account on the
  host. Instead the user typically enters 'anonymous' or 'ftp' when prompted for username. Although
  users are commonly asked to send their email address as their password, little to no verification
  is actually performed on the supplied data.

  Remark: NIST don't see 'configuration issues' as software flaws so the referenced CVE has a
  severity of 0.0. The severity of this VT has been raised by Greenbone to still report a
  configuration issue on the target.","
Details:
Anonymous FTP Login Reporting
(OID: 1.3.6.1.4.1.25623.1.0.900600)
Version used: 2021-10-20T09:03:29Z
","","","",""
192.168.1.29,,80,tcp,6.1,Medium,80,"VendorFix","TWiki < 6.1.0 XSS Vulnerability","bin/statistics in TWiki 6.0.2 allows XSS via the webs parameter.","Installed version: 01.Feb.2003
Fixed version:     6.1.0

",1.3.6.1.4.1.25623.1.0.141830,"CVE-2018-20212",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,637bd202-fd84-4060-8054-9099aaf16838,"","Update to version 6.1.0 or later.","TWiki version 6.0.2 and probably prior.","","Checks if a vulnerable version is present on the target host.
Details:
TWiki < 6.1.0 XSS Vulnerability
(OID: 1.3.6.1.4.1.25623.1.0.141830)
Version used: 2023-07-14T16:09:27Z
","","","",""
192.168.1.29,,80,tcp,6.1,Medium,80,"VendorFix","jQuery < 1.9.0 XSS Vulnerability","jQuery is prone to a cross-site scripting (XSS)
  vulnerability.","Installed version: 1.3.2
Fixed version:     1.9.0
Installation
path / port:       /mutillidae/javascript/ddsmoothmenu/jquery.min.js

Detection info (see OID: 1.3.6.1.4.1.25623.1.0.150658 for more info):
- Identified file: http://192.168.1.29/mutillidae/javascript/ddsmoothmenu/jquery.min.js
- Referenced at:   http://192.168.1.29/mutillidae/
",1.3.6.1.4.1.25623.1.0.141636,"CVE-2012-6708",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,bddec9a2-682a-4737-81d2-ab0e30aca0fa,"","Update to version 1.9.0 or later.","jQuery prior to version 1.9.0.","The jQuery(strInput) function does not differentiate selectors
  from HTML in a reliable fashion. In vulnerable versions, jQuery determined whether the input was
  HTML by looking for the '<' character anywhere in the string, giving attackers more flexibility
  when attempting to construct a malicious payload. In fixed versions, jQuery only deems the input
  to be HTML if it explicitly starts with the '<' character, limiting exploitability only to
  attackers who can control the beginning of a string, which is far less common.","Checks if a vulnerable version is present on the target host.
Details:
jQuery < 1.9.0 XSS Vulnerability
(OID: 1.3.6.1.4.1.25623.1.0.141636)
Version used: 2023-07-14T05:06:08Z
","","","DFN-CERT-2023-1197,DFN-CERT-2020-0590,WID-SEC-2022-0673,CB-K22/0045,CB-K18/1131",""
192.168.1.29,,80,tcp,6.0,Medium,80,"VendorFix","TWiki Cross-Site Request Forgery Vulnerability","TWiki is prone to a cross-site request forgery (CSRF) vulnerability.","Installed version: 01.Feb.2003
Fixed version:     4.3.1

",1.3.6.1.4.1.25623.1.0.800400,"CVE-2009-1339",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,8781abc3-8080-4821-8190-029b74d1ebfc,"Successful exploitation will allow attacker to gain administrative
  privileges on the target application and can cause CSRF attack.","Upgrade to version 4.3.1 or later.","TWiki version prior to 4.3.1","Remote authenticated user can create a specially crafted image tag that,
  when viewed by the target user, will update pages on the target system with the privileges of the target user
  via HTTP requests.","
Details:
TWiki Cross-Site Request Forgery Vulnerability
(OID: 1.3.6.1.4.1.25623.1.0.800400)
Version used: 2024-03-04T14:37:58Z
","","","",""
192.168.1.29,,5432,tcp,5.9,Medium,98,"Mitigation","SSL/TLS: Report Weak Cipher Suites","This routine reports all Weak SSL/TLS cipher suites accepted
  by a service.

  NOTE: No severity for SMTP services with 'Opportunistic TLS' and weak cipher suites on port
  25/tcp is reported. If too strong cipher suites are configured for this service the alternative
  would be to fall back to an even more insecure cleartext communication.","'Weak' cipher suites accepted by this service via the SSLv3 protocol:

TLS_RSA_WITH_RC4_128_SHA

'Weak' cipher suites accepted by this service via the TLSv1.0 protocol:

TLS_RSA_WITH_RC4_128_SHA


",1.3.6.1.4.1.25623.1.0.103440,"CVE-2013-2566,CVE-2015-2808,CVE-2015-4000",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,7d1054a6-bfde-4048-bb11-b7f90eb48645,"","The configuration of this services should be changed so
  that it does not accept the listed weak cipher suites anymore.

  Please see the references for more resources supporting you with this task.","","These rules are applied for the evaluation of the cryptographic
  strength:

  - RC4 is considered to be weak (CVE-2013-2566, CVE-2015-2808)

  - Ciphers using 64 bit or less are considered to be vulnerable to brute force methods
  and therefore considered as weak (CVE-2015-4000)

  - 1024 bit RSA authentication is considered to be insecure and therefore as weak

  - Any cipher considered to be secure for only the next 10 years is considered as medium

  - Any other cipher is considered as strong","
Details:
SSL/TLS: Report Weak Cipher Suites
(OID: 1.3.6.1.4.1.25623.1.0.103440)
Version used: 2023-11-02T05:05:26Z
","","","DFN-CERT-2023-2939,DFN-CERT-2021-0775,DFN-CERT-2020-1561,DFN-CERT-2020-1276,DFN-CERT-2017-1821,DFN-CERT-2016-1692,DFN-CERT-2016-1648,DFN-CERT-2016-1168,DFN-CERT-2016-0665,DFN-CERT-2016-0642,DFN-CERT-2016-0184,DFN-CERT-2016-0135,DFN-CERT-2016-0101,DFN-CERT-2016-0035,DFN-CERT-2015-1853,DFN-CERT-2015-1679,DFN-CERT-2015-1632,DFN-CERT-2015-1608,DFN-CERT-2015-1542,DFN-CERT-2015-1518,DFN-CERT-2015-1406,DFN-CERT-2015-1341,DFN-CERT-2015-1194,DFN-CERT-2015-1144,DFN-CERT-2015-1113,DFN-CERT-2015-1078,DFN-CERT-2015-1067,DFN-CERT-2015-1038,DFN-CERT-2015-1016,DFN-CERT-2015-1012,DFN-CERT-2015-0980,DFN-CERT-2015-0977,DFN-CERT-2015-0976,DFN-CERT-2015-0960,DFN-CERT-2015-0956,DFN-CERT-2015-0944,DFN-CERT-2015-0937,DFN-CERT-2015-0925,DFN-CERT-2015-0884,DFN-CERT-2015-0881,DFN-CERT-2015-0879,DFN-CERT-2015-0866,DFN-CERT-2015-0844,DFN-CERT-2015-0800,DFN-CERT-2015-0737,DFN-CERT-2015-0696,DFN-CERT-2014-0977,CB-K21/0067,CB-K19/0812,CB-K17/1750,CB-K16/1593,CB-K16/1552,CB-K16/1102,CB-K16/0617,CB-K16/0599,CB-K16/0168,CB-K16/0121,CB-K16/0090,CB-K16/0030,CB-K15/1751,CB-K15/1591,CB-K15/1550,CB-K15/1517,CB-K15/1514,CB-K15/1464,CB-K15/1442,CB-K15/1334,CB-K15/1269,CB-K15/1136,CB-K15/1090,CB-K15/1059,CB-K15/1022,CB-K15/1015,CB-K15/0986,CB-K15/0964,CB-K15/0962,CB-K15/0932,CB-K15/0927,CB-K15/0926,CB-K15/0907,CB-K15/0901,CB-K15/0896,CB-K15/0889,CB-K15/0877,CB-K15/0850,CB-K15/0849,CB-K15/0834,CB-K15/0827,CB-K15/0802,CB-K15/0764,CB-K15/0733,CB-K15/0667,CB-K14/0935,CB-K13/0942",""
192.168.1.29,,5432,tcp,5.9,Medium,98,"Mitigation","SSL/TLS: Deprecated SSLv2 and SSLv3 Protocol Detection","It was possible to detect the usage of the deprecated SSLv2
  and/or SSLv3 protocol on this system.","In addition to TLSv1.0+ the service is also providing the deprecated SSLv3 protocol and supports one or more ciphers. Those supported ciphers can be found in the 'SSL/TLS: Report Supported Cipher Suites' (OID: 1.3.6.1.4.1.25623.1.0.802067) VT.
",1.3.6.1.4.1.25623.1.0.111012,"CVE-2016-0800,CVE-2014-3566",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,18392db3-4037-4e6d-9af3-49943d8bf3c4,"An attacker might be able to use the known cryptographic flaws to
  eavesdrop the connection between clients and the service to get access to sensitive data
  transferred within the secured connection.

  Furthermore newly uncovered vulnerabilities in this protocols won't receive security updates
  anymore.","It is recommended to disable the deprecated SSLv2 and/or SSLv3
  protocols in favor of the TLSv1.2+ protocols. Please see the references for more information.","All services providing an encrypted communication using the
  SSLv2 and/or SSLv3 protocols.","The SSLv2 and SSLv3 protocols contain known cryptographic
  flaws like:

  - CVE-2014-3566: Padding Oracle On Downgraded Legacy Encryption (POODLE)

  - CVE-2016-0800: Decrypting RSA with Obsolete and Weakened eNcryption (DROWN)","Check the used SSL protocols of the services provided by this
  system.
Details:
SSL/TLS: Deprecated SSLv2 and SSLv3 Protocol Detection
(OID: 1.3.6.1.4.1.25623.1.0.111012)
Version used: 2021-10-15T12:51:02Z
","","","DFN-CERT-2018-0096,DFN-CERT-2017-1238,DFN-CERT-2017-1236,DFN-CERT-2016-1929,DFN-CERT-2016-1527,DFN-CERT-2016-1468,DFN-CERT-2016-1216,DFN-CERT-2016-1174,DFN-CERT-2016-1168,DFN-CERT-2016-0884,DFN-CERT-2016-0841,DFN-CERT-2016-0644,DFN-CERT-2016-0642,DFN-CERT-2016-0496,DFN-CERT-2016-0495,DFN-CERT-2016-0465,DFN-CERT-2016-0459,DFN-CERT-2016-0453,DFN-CERT-2016-0451,DFN-CERT-2016-0415,DFN-CERT-2016-0403,DFN-CERT-2016-0388,DFN-CERT-2016-0360,DFN-CERT-2016-0359,DFN-CERT-2016-0357,DFN-CERT-2016-0171,DFN-CERT-2015-1431,DFN-CERT-2015-1075,DFN-CERT-2015-1026,DFN-CERT-2015-0664,DFN-CERT-2015-0548,DFN-CERT-2015-0404,DFN-CERT-2015-0396,DFN-CERT-2015-0259,DFN-CERT-2015-0254,DFN-CERT-2015-0245,DFN-CERT-2015-0118,DFN-CERT-2015-0114,DFN-CERT-2015-0083,DFN-CERT-2015-0082,DFN-CERT-2015-0081,DFN-CERT-2015-0076,DFN-CERT-2014-1717,DFN-CERT-2014-1680,DFN-CERT-2014-1632,DFN-CERT-2014-1564,DFN-CERT-2014-1542,DFN-CERT-2014-1414,DFN-CERT-2014-1366,DFN-CERT-2014-1354,WID-SEC-2023-0431,WID-SEC-2023-0427,CB-K18/0094,CB-K17/1198,CB-K17/1196,CB-K16/1828,CB-K16/1438,CB-K16/1384,CB-K16/1141,CB-K16/1107,CB-K16/1102,CB-K16/0792,CB-K16/0599,CB-K16/0597,CB-K16/0459,CB-K16/0456,CB-K16/0433,CB-K16/0424,CB-K16/0415,CB-K16/0413,CB-K16/0374,CB-K16/0367,CB-K16/0331,CB-K16/0329,CB-K16/0328,CB-K16/0156,CB-K15/1514,CB-K15/1358,CB-K15/1021,CB-K15/0972,CB-K15/0637,CB-K15/0590,CB-K15/0525,CB-K15/0393,CB-K15/0384,CB-K15/0287,CB-K15/0252,CB-K15/0246,CB-K15/0237,CB-K15/0118,CB-K15/0110,CB-K15/0108,CB-K15/0080,CB-K15/0078,CB-K15/0077,CB-K15/0075,CB-K14/1617,CB-K14/1581,CB-K14/1537,CB-K14/1479,CB-K14/1458,CB-K14/1342,CB-K14/1314,CB-K14/1313,CB-K14/1311,CB-K14/1304,CB-K14/1296",""
192.168.1.29,,25,tcp,5.9,Medium,98,"Mitigation","SSL/TLS: Deprecated SSLv2 and SSLv3 Protocol Detection","It was possible to detect the usage of the deprecated SSLv2
  and/or SSLv3 protocol on this system.","In addition to TLSv1.0+ the service is also providing the deprecated SSLv2 and SSLv3 protocols and supports one or more ciphers. Those supported ciphers can be found in the 'SSL/TLS: Report Supported Cipher Suites' (OID: 1.3.6.1.4.1.25623.1.0.802067) VT.
",1.3.6.1.4.1.25623.1.0.111012,"CVE-2016-0800,CVE-2014-3566",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,ebc425f9-6a98-4e8a-a7ac-42a943db9d09,"An attacker might be able to use the known cryptographic flaws to
  eavesdrop the connection between clients and the service to get access to sensitive data
  transferred within the secured connection.

  Furthermore newly uncovered vulnerabilities in this protocols won't receive security updates
  anymore.","It is recommended to disable the deprecated SSLv2 and/or SSLv3
  protocols in favor of the TLSv1.2+ protocols. Please see the references for more information.","All services providing an encrypted communication using the
  SSLv2 and/or SSLv3 protocols.","The SSLv2 and SSLv3 protocols contain known cryptographic
  flaws like:

  - CVE-2014-3566: Padding Oracle On Downgraded Legacy Encryption (POODLE)

  - CVE-2016-0800: Decrypting RSA with Obsolete and Weakened eNcryption (DROWN)","Check the used SSL protocols of the services provided by this
  system.
Details:
SSL/TLS: Deprecated SSLv2 and SSLv3 Protocol Detection
(OID: 1.3.6.1.4.1.25623.1.0.111012)
Version used: 2021-10-15T12:51:02Z
","","","DFN-CERT-2018-0096,DFN-CERT-2017-1238,DFN-CERT-2017-1236,DFN-CERT-2016-1929,DFN-CERT-2016-1527,DFN-CERT-2016-1468,DFN-CERT-2016-1216,DFN-CERT-2016-1174,DFN-CERT-2016-1168,DFN-CERT-2016-0884,DFN-CERT-2016-0841,DFN-CERT-2016-0644,DFN-CERT-2016-0642,DFN-CERT-2016-0496,DFN-CERT-2016-0495,DFN-CERT-2016-0465,DFN-CERT-2016-0459,DFN-CERT-2016-0453,DFN-CERT-2016-0451,DFN-CERT-2016-0415,DFN-CERT-2016-0403,DFN-CERT-2016-0388,DFN-CERT-2016-0360,DFN-CERT-2016-0359,DFN-CERT-2016-0357,DFN-CERT-2016-0171,DFN-CERT-2015-1431,DFN-CERT-2015-1075,DFN-CERT-2015-1026,DFN-CERT-2015-0664,DFN-CERT-2015-0548,DFN-CERT-2015-0404,DFN-CERT-2015-0396,DFN-CERT-2015-0259,DFN-CERT-2015-0254,DFN-CERT-2015-0245,DFN-CERT-2015-0118,DFN-CERT-2015-0114,DFN-CERT-2015-0083,DFN-CERT-2015-0082,DFN-CERT-2015-0081,DFN-CERT-2015-0076,DFN-CERT-2014-1717,DFN-CERT-2014-1680,DFN-CERT-2014-1632,DFN-CERT-2014-1564,DFN-CERT-2014-1542,DFN-CERT-2014-1414,DFN-CERT-2014-1366,DFN-CERT-2014-1354,WID-SEC-2023-0431,WID-SEC-2023-0427,CB-K18/0094,CB-K17/1198,CB-K17/1196,CB-K16/1828,CB-K16/1438,CB-K16/1384,CB-K16/1141,CB-K16/1107,CB-K16/1102,CB-K16/0792,CB-K16/0599,CB-K16/0597,CB-K16/0459,CB-K16/0456,CB-K16/0433,CB-K16/0424,CB-K16/0415,CB-K16/0413,CB-K16/0374,CB-K16/0367,CB-K16/0331,CB-K16/0329,CB-K16/0328,CB-K16/0156,CB-K15/1514,CB-K15/1358,CB-K15/1021,CB-K15/0972,CB-K15/0637,CB-K15/0590,CB-K15/0525,CB-K15/0393,CB-K15/0384,CB-K15/0287,CB-K15/0252,CB-K15/0246,CB-K15/0237,CB-K15/0118,CB-K15/0110,CB-K15/0108,CB-K15/0080,CB-K15/0078,CB-K15/0077,CB-K15/0075,CB-K14/1617,CB-K14/1581,CB-K14/1537,CB-K14/1479,CB-K14/1458,CB-K14/1342,CB-K14/1314,CB-K14/1313,CB-K14/1311,CB-K14/1304,CB-K14/1296",""
192.168.1.29,,80,tcp,5.8,Medium,99,"Mitigation","HTTP Debugging Methods (TRACE/TRACK) Enabled","The remote web server supports the TRACE and/or TRACK
  methods. TRACE and TRACK are HTTP methods which are used to debug web server connections.","The web server has the following HTTP methods enabled: TRACE
",1.3.6.1.4.1.25623.1.0.11213,"CVE-2003-1567,CVE-2004-2320,CVE-2004-2763,CVE-2005-3398,CVE-2006-4683,CVE-2007-3008,CVE-2008-7253,CVE-2009-2823,CVE-2010-0386,CVE-2012-2223,CVE-2014-7883",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,a7abafc1-60bb-422f-9905-fb807a6e8ee8,"An attacker may use this flaw to trick your legitimate web
  users to give him their credentials.","Disable the TRACE and TRACK methods in your web server
  configuration.

  Please see the manual of your web server or the references for more information.","Web servers with enabled TRACE and/or TRACK methods.","It has been shown that web servers supporting this methods
  are subject to cross-site-scripting attacks, dubbed XST for Cross-Site-Tracing, when used in
  conjunction with various weaknesses in browsers.","Checks if HTTP methods such as TRACE and TRACK are
  enabled and can be used.
Details:
HTTP Debugging Methods (TRACE/TRACK) Enabled
(OID: 1.3.6.1.4.1.25623.1.0.11213)
Version used: 2023-08-01T13:29:10Z
","","","DFN-CERT-2021-1825,DFN-CERT-2014-1018,DFN-CERT-2010-0020,CB-K14/0981",""
192.168.1.29,,5432,tcp,5.3,Medium,80,"Mitigation","SSL/TLS: Server Certificate / Certificate in Chain with RSA keys less than 2048 bits","The remote SSL/TLS server certificate and/or any of the
  certificates in the certificate chain is using a RSA key with less than 2048 bits.","The remote SSL/TLS server is using the following certificate(s) with a RSA key with less than 2048 bits (public-key-size:public-key-algorithm:serial:issuer):

1024:RSA:00FAF93A4C7FB6B9CC:1.2.840.113549.1.9.1=#726F6F74407562756E74753830342D626173652E6C6F63616C646F6D61696E,CN=ubuntu804-base.localdomain,OU=Office for Complication of Otherwise Simple Affairs,O=OCOSA,L=Everywhere,ST=There is no such thing outside US,C=XX (Server certificate)
",1.3.6.1.4.1.25623.1.0.150710,"",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,ce4a311a-3097-4c32-9349-d46e1379ddec,"Using certificates with weak RSA key size can lead to
  unauthorized exposure of sensitive information.","Replace the certificate with a stronger key and reissue the
  certificates it signed.","","SSL/TLS certificates using RSA keys with less than 2048 bits are
  considered unsafe.","Checks the RSA keys size of the server certificate and all
  certificates in chain for a size < 2048 bit.
Details:
SSL/TLS: Server Certificate / Certificate in Chain with RSA keys less than 2...
(OID: 1.3.6.1.4.1.25623.1.0.150710)
Version used: 2021-12-10T12:48:00Z
","","","",""
192.168.1.29,,25,tcp,5.3,Medium,80,"Mitigation","SSL/TLS: Server Certificate / Certificate in Chain with RSA keys less than 2048 bits","The remote SSL/TLS server certificate and/or any of the
  certificates in the certificate chain is using a RSA key with less than 2048 bits.","The remote SSL/TLS server is using the following certificate(s) with a RSA key with less than 2048 bits (public-key-size:public-key-algorithm:serial:issuer):

1024:RSA:00FAF93A4C7FB6B9CC:1.2.840.113549.1.9.1=#726F6F74407562756E74753830342D626173652E6C6F63616C646F6D61696E,CN=ubuntu804-base.localdomain,OU=Office for Complication of Otherwise Simple Affairs,O=OCOSA,L=Everywhere,ST=There is no such thing outside US,C=XX (Server certificate)
",1.3.6.1.4.1.25623.1.0.150710,"",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,ab1dd496-db93-468b-91a2-a6e1009710e9,"Using certificates with weak RSA key size can lead to
  unauthorized exposure of sensitive information.","Replace the certificate with a stronger key and reissue the
  certificates it signed.","","SSL/TLS certificates using RSA keys with less than 2048 bits are
  considered unsafe.","Checks the RSA keys size of the server certificate and all
  certificates in chain for a size < 2048 bit.
Details:
SSL/TLS: Server Certificate / Certificate in Chain with RSA keys less than 2...
(OID: 1.3.6.1.4.1.25623.1.0.150710)
Version used: 2021-12-10T12:48:00Z
","","","",""
192.168.1.29,,22,tcp,5.3,Medium,80,"Mitigation","Weak Host Key Algorithm(s) (SSH)","The remote SSH server is configured to allow / support weak host
  key algorithm(s).","The remote SSH server supports the following weak host key algorithm(s):

host key algorithm | Description
-----------------------------------------------------------------------------------------
ssh-dss            | Digital Signature Algorithm (DSA) / Digital Signature Standard (DSS)
",1.3.6.1.4.1.25623.1.0.117687,"",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,4addb50a-f94f-49bb-b95e-b8fda1c40645,"","Disable the reported weak host key algorithm(s).","","","Checks the supported host key algorithms of the remote SSH
  server.

  Currently weak host key algorithms are defined as the following:

  - ssh-dss: Digital Signature Algorithm (DSA) / Digital Signature Standard (DSS)
Details:
Weak Host Key Algorithm(s) (SSH)
(OID: 1.3.6.1.4.1.25623.1.0.117687)
Version used: 2023-10-12T05:05:32Z
","","","",""
192.168.1.29,,22,tcp,5.3,Medium,80,"Mitigation","Weak Key Exchange (KEX) Algorithm(s) Supported (SSH)","The remote SSH server is configured to allow / support weak key
  exchange (KEX) algorithm(s).","The remote SSH server supports the following weak KEX algorithm(s):

KEX algorithm                      | Reason
-------------------------------------------------------------------------------------------
diffie-hellman-group-exchange-sha1 | Using SHA-1
diffie-hellman-group1-sha1         | Using Oakley Group 2 (a 1024-bit MODP group) and SHA-1
",1.3.6.1.4.1.25623.1.0.150713,"",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,e1b7273d-5545-4ba7-a124-e3f428e536a9,"An attacker can quickly break individual connections.","Disable the reported weak KEX algorithm(s)

  - 1024-bit MODP group / prime KEX algorithms:

  Alternatively use elliptic-curve Diffie-Hellmann in general, e.g. Curve 25519.","","'- 1024-bit MODP group / prime KEX algorithms:

  Millions of HTTPS, SSH, and VPN servers all use the same prime numbers for Diffie-Hellman key
  exchange. Practitioners believed this was safe as long as new key exchange messages were generated
  for every connection. However, the first step in the number field sieve-the most efficient
  algorithm for breaking a Diffie-Hellman connection-is dependent only on this prime.

  A nation-state can break a 1024-bit prime.","Checks the supported KEX algorithms of the remote SSH server.

  Currently weak KEX algorithms are defined as the following:

  - non-elliptic-curve Diffie-Hellmann (DH) KEX algorithms with 1024-bit MODP group / prime

  - ephemerally generated key exchange groups uses SHA-1

  - using RSA 1024-bit modulus key
Details:
Weak Key Exchange (KEX) Algorithm(s) Supported (SSH)
(OID: 1.3.6.1.4.1.25623.1.0.150713)
Version used: 2023-10-12T05:05:32Z
","","","",""
192.168.1.29,,80,tcp,5.3,Medium,80,"Workaround","phpinfo() Output Reporting (HTTP)","Reporting of files containing the output of the phpinfo() PHP
  function previously detected via HTTP.","The following files are calling the function phpinfo() which disclose potentially sensitive information:

http://192.168.1.29/mutillidae/phpinfo.php
Concluded from:
  <title>phpinfo()</title><meta name=""ROBOTS"" content=""NOINDEX,NOFOLLOW,NOARCHIVE"" /></head>
  <tr><td class=""e"">Configuration File (php.ini) Path </td><td class=""v"">/etc/php5/cgi </td></tr>
  <h2>PHP Variables</h2>
http://192.168.1.29/phpinfo.php
Concluded from:
  <title>phpinfo()</title><meta name=""ROBOTS"" content=""NOINDEX,NOFOLLOW,NOARCHIVE"" /></head>
  <tr><td class=""e"">Configuration File (php.ini) Path </td><td class=""v"">/etc/php5/cgi </td></tr>
  <h2>PHP Variables</h2>
",1.3.6.1.4.1.25623.1.0.11229,"CVE-2008-0149,CVE-2023-49282,CVE-2023-49283",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,1b2cbde1-1ae4-479c-8ab4-c739761b1781,"Some of the information that can be gathered from this file includes:

  The username of the user running the PHP process, if it is a sudo user, the IP address of the host, the web server
  version, the system version (Unix, Linux, Windows, ...), and the root directory of the web server.","Delete the listed files or restrict access to them.","All systems exposing a file containing the output of the
  phpinfo() PHP function.

  This VT is also reporting if an affected endpoint for the following products have been identified:

  - CVE-2008-0149: TUTOS

  - CVE-2023-49282, CVE-2023-49283: Microsoft Graph PHP SDK","Many PHP installation tutorials instruct the user to create a
  file called phpinfo.php or similar containing the phpinfo() statement. Such a file is often left
  back in the webserver directory.","This script reports files identified by the following separate
  VT: 'phpinfo() Output Detection (HTTP)' (OID: 1.3.6.1.4.1.25623.1.0.108474).
Details:
phpinfo() Output Reporting (HTTP)
(OID: 1.3.6.1.4.1.25623.1.0.11229)
Version used: 2023-12-14T08:20:35Z
","","","",""
192.168.1.29,,25,tcp,5.0,Medium,99,"Workaround","Check if Mailserver answer to VRFY and EXPN requests","The Mailserver on this host answers to VRFY and/or EXPN requests.","'VRFY root' produces the following answer: 252 2.0.0 root


",1.3.6.1.4.1.25623.1.0.100072,"",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,d992f4a7-1579-466a-b60c-c3c3e601f886,"","Disable VRFY and/or EXPN on your Mailserver.

  For postfix add 'disable_vrfy_command=yes' in 'main.cf'.

  For Sendmail add the option 'O PrivacyOptions=goaway'.

  It is suggested that, if you really want to publish this type of information, you use a mechanism
  that legitimate users actually know about, such as Finger or HTTP.","","VRFY and EXPN ask the server for information about an address. They are
  inherently unusable through firewalls, gateways, mail exchangers for part-time hosts, etc.","
Details:
Check if Mailserver answer to VRFY and EXPN requests
(OID: 1.3.6.1.4.1.25623.1.0.100072)
Version used: 2023-10-31T05:06:37Z
","","","",""
192.168.1.29,,5432,tcp,5.0,Medium,99,"Mitigation","SSL/TLS: Certificate Expired","The remote server's SSL/TLS certificate has already expired.","The certificate of the remote service expired on 2010-04-16 14:07:45.

Certificate details:
fingerprint (SHA-1)             | ED093088706603BFD5DC237399B498DA2D4D31C6
fingerprint (SHA-256)           | E7A7FA0D63E457C7C4A59B38B70849C6A70BDA6F830C7AF1E32DEE436DE813CC
issued by                       | 1.2.840.113549.1.9.1=#726F6F74407562756E74753830342D626173652E6C6F63616C646F6D61696E,CN=ubuntu804-base.localdomain,OU=Office for Complication of Otherwise Simple Affairs,O=OCOSA,L=Everywhere,ST=There is no such thing outside US,C=XX
public key algorithm            | RSA
public key size (bits)          | 1024
serial                          | 00FAF93A4C7FB6B9CC
signature algorithm             | sha1WithRSAEncryption
subject                         | 1.2.840.113549.1.9.1=#726F6F74407562756E74753830342D626173652E6C6F63616C646F6D61696E,CN=ubuntu804-base.localdomain,OU=Office for Complication of Otherwise Simple Affairs,O=OCOSA,L=Everywhere,ST=There is no such thing outside US,C=XX
subject alternative names (SAN) | None
valid from                      | 2010-03-17 14:07:45 UTC
valid until                     | 2010-04-16 14:07:45 UTC
",1.3.6.1.4.1.25623.1.0.103955,"",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,2ec287f8-b8b1-40f3-b251-5040c1e7d22b,"","Replace the SSL/TLS certificate by a new one.","","This script checks expiry dates of certificates associated with
  SSL/TLS-enabled services on the target and reports whether any have already expired.","
Details:
SSL/TLS: Certificate Expired
(OID: 1.3.6.1.4.1.25623.1.0.103955)
Version used: 2021-11-22T15:32:39Z
","","","",""
192.168.1.29,,25,tcp,5.0,Medium,99,"Mitigation","SSL/TLS: Certificate Expired","The remote server's SSL/TLS certificate has already expired.","The certificate of the remote service expired on 2010-04-16 14:07:45.

Certificate details:
fingerprint (SHA-1)             | ED093088706603BFD5DC237399B498DA2D4D31C6
fingerprint (SHA-256)           | E7A7FA0D63E457C7C4A59B38B70849C6A70BDA6F830C7AF1E32DEE436DE813CC
issued by                       | 1.2.840.113549.1.9.1=#726F6F74407562756E74753830342D626173652E6C6F63616C646F6D61696E,CN=ubuntu804-base.localdomain,OU=Office for Complication of Otherwise Simple Affairs,O=OCOSA,L=Everywhere,ST=There is no such thing outside US,C=XX
public key algorithm            | RSA
public key size (bits)          | 1024
serial                          | 00FAF93A4C7FB6B9CC
signature algorithm             | sha1WithRSAEncryption
subject                         | 1.2.840.113549.1.9.1=#726F6F74407562756E74753830342D626173652E6C6F63616C646F6D61696E,CN=ubuntu804-base.localdomain,OU=Office for Complication of Otherwise Simple Affairs,O=OCOSA,L=Everywhere,ST=There is no such thing outside US,C=XX
subject alternative names (SAN) | None
valid from                      | 2010-03-17 14:07:45 UTC
valid until                     | 2010-04-16 14:07:45 UTC
",1.3.6.1.4.1.25623.1.0.103955,"",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,576be4ee-0c95-4286-bf1b-cd3edfc63eef,"","Replace the SSL/TLS certificate by a new one.","","This script checks expiry dates of certificates associated with
  SSL/TLS-enabled services on the target and reports whether any have already expired.","
Details:
SSL/TLS: Certificate Expired
(OID: 1.3.6.1.4.1.25623.1.0.103955)
Version used: 2021-11-22T15:32:39Z
","","","",""
192.168.1.29,,25,tcp,5.0,Medium,70,"VendorFix","SSL/TLS: Renegotiation DoS Vulnerability (CVE-2011-1473, CVE-2011-5094)","The remote SSL/TLS service is prone to a denial of service (DoS)
  vulnerability.","The following indicates that the remote SSL/TLS service is affected:

Protocol Version | Successful re-done SSL/TLS handshakes (Renegotiation) over an existing / already established SSL/TLS connection
----------------------------------------------------------------------------------------------------------------------------------
TLSv1.0          | 10
",1.3.6.1.4.1.25623.1.0.117761,"CVE-2011-1473,CVE-2011-5094",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,26c0348e-e197-4852-91e6-f18fd065ee05,"The flaw might make it easier for remote attackers to cause a
  DoS (CPU consumption) by performing many renegotiations within a single connection.","Users should contact their vendors for specific patch information.

  A general solution is to remove/disable renegotiation capabilities altogether from/in the affected
  SSL/TLS service.","Every SSL/TLS service which does not properly restrict
  client-initiated renegotiation.","The flaw exists because the remote SSL/TLS service does not
  properly restrict client-initiated renegotiation within the SSL and TLS protocols.

  Note: The referenced CVEs are affecting OpenSSL and Mozilla Network Security Services (NSS) but
  both are in a DISPUTED state with the following rationale:

  > It can also be argued that it is the responsibility of server deployments, not a security
  library, to prevent or limit renegotiation when it is inappropriate within a specific environment.

  Both CVEs are still kept in this VT as a reference to the origin of this flaw.","Checks if the remote service allows to re-do the same SSL/TLS
  handshake (Renegotiation) over an existing / already established SSL/TLS connection.
Details:
SSL/TLS: Renegotiation DoS Vulnerability (CVE-2011-1473, CVE-2011-5094)
(OID: 1.3.6.1.4.1.25623.1.0.117761)
Version used: 2024-02-02T05:06:11Z
","","","DFN-CERT-2017-1013,DFN-CERT-2017-1012,DFN-CERT-2014-0809,DFN-CERT-2013-1928,DFN-CERT-2012-1112,WID-SEC-2024-0796,WID-SEC-2023-1435,CB-K17/0980,CB-K17/0979,CB-K14/0772,CB-K13/0915,CB-K13/0462",""
192.168.1.29,,5432,tcp,5.0,Medium,70,"VendorFix","SSL/TLS: Renegotiation DoS Vulnerability (CVE-2011-1473, CVE-2011-5094)","The remote SSL/TLS service is prone to a denial of service (DoS)
  vulnerability.","The following indicates that the remote SSL/TLS service is affected:

Protocol Version | Successful re-done SSL/TLS handshakes (Renegotiation) over an existing / already established SSL/TLS connection
----------------------------------------------------------------------------------------------------------------------------------
TLSv1.0          | 10
",1.3.6.1.4.1.25623.1.0.117761,"CVE-2011-1473,CVE-2011-5094",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,5b826dda-fc25-448e-845a-34c94189d7ca,"The flaw might make it easier for remote attackers to cause a
  DoS (CPU consumption) by performing many renegotiations within a single connection.","Users should contact their vendors for specific patch information.

  A general solution is to remove/disable renegotiation capabilities altogether from/in the affected
  SSL/TLS service.","Every SSL/TLS service which does not properly restrict
  client-initiated renegotiation.","The flaw exists because the remote SSL/TLS service does not
  properly restrict client-initiated renegotiation within the SSL and TLS protocols.

  Note: The referenced CVEs are affecting OpenSSL and Mozilla Network Security Services (NSS) but
  both are in a DISPUTED state with the following rationale:

  > It can also be argued that it is the responsibility of server deployments, not a security
  library, to prevent or limit renegotiation when it is inappropriate within a specific environment.

  Both CVEs are still kept in this VT as a reference to the origin of this flaw.","Checks if the remote service allows to re-do the same SSL/TLS
  handshake (Renegotiation) over an existing / already established SSL/TLS connection.
Details:
SSL/TLS: Renegotiation DoS Vulnerability (CVE-2011-1473, CVE-2011-5094)
(OID: 1.3.6.1.4.1.25623.1.0.117761)
Version used: 2024-02-02T05:06:11Z
","","","DFN-CERT-2017-1013,DFN-CERT-2017-1012,DFN-CERT-2014-0809,DFN-CERT-2013-1928,DFN-CERT-2012-1112,WID-SEC-2024-0796,WID-SEC-2023-1435,CB-K17/0980,CB-K17/0979,CB-K14/0772,CB-K13/0915,CB-K13/0462",""
192.168.1.29,,80,tcp,5.0,Medium,99,"WillNotFix","QWikiwiki directory traversal vulnerability","The remote host is running QWikiwiki, a Wiki application written in PHP.

  The remote version of this software contains a validation input flaw which may allow an attacker
  to use it to read arbitrary files on the remote host with the privileges of the web server.","Vulnerable URL: http://192.168.1.29/mutillidae/index.php?page=../../../../../../../../../../../etc/passwd%00
",1.3.6.1.4.1.25623.1.0.16100,"CVE-2005-0283",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,17e6a89b-57ac-41e2-9396-ff701d3da169,"","No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.","","","
Details:
QWikiwiki directory traversal vulnerability
(OID: 1.3.6.1.4.1.25623.1.0.16100)
Version used: 2023-12-13T05:05:23Z
","","","",""
192.168.1.29,,80,tcp,5.0,Medium,99,"WillNotFix","awiki <= 20100125 Multiple LFI Vulnerabilities - Active Check","awiki is prone to multiple local file include (LFI)
  vulnerabilities because it fails to properly sanitize user-supplied input.","Vulnerable URL: http://192.168.1.29/mutillidae/index.php?page=/etc/passwd
",1.3.6.1.4.1.25623.1.0.103210,"",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,bce87c2e-9246-4645-9988-a19fab56da89,"An attacker can exploit this vulnerability to obtain potentially
  sensitive information and execute arbitrary local scripts in the context of the webserver
  process. This may allow the attacker to compromise the application and the host.","No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.","awiki version 20100125 and prior.","","Sends a crafted HTTP GET request and checks the response.
Details:
awiki <= 20100125 Multiple LFI Vulnerabilities - Active Check
(OID: 1.3.6.1.4.1.25623.1.0.103210)
Version used: 2023-12-13T05:05:23Z
","","","",""
192.168.1.29,,80,tcp,5.0,Medium,80,"Mitigation","/doc directory browsable","The /doc directory is browsable.
  /doc shows the content of the /usr/doc directory and therefore it shows which programs and - important! - the version of the installed programs.","Vulnerable URL: http://192.168.1.29/doc/
",1.3.6.1.4.1.25623.1.0.10056,"CVE-1999-0678",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,c326ec52-6653-4155-b150-ec411f1ccdab,"","Use access restrictions for the /doc directory.
  If you use Apache you might use this in your access.conf:

  <Directory /usr/doc>
  AllowOverride None
  order deny, allow
  deny from all
  allow from localhost
  </Directory>","","","
Details:
/doc directory browsable
(OID: 1.3.6.1.4.1.25623.1.0.10056)
Version used: 2023-08-01T13:29:10Z
","","","",""
192.168.1.29,,5900,tcp,4.8,Medium,70,"Mitigation","VNC Server Unencrypted Data Transmission","The remote host is running a VNC server providing one or more insecure or
  cryptographically weak Security Type(s) not intended for use on untrusted networks.","The VNC server provides the following insecure or cryptographically weak Security Type(s):

2 (VNC authentication)
",1.3.6.1.4.1.25623.1.0.108529,"",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,6fb3e949-0bf2-4a5e-953b-7594c33f18bd,"An attacker can uncover sensitive data by sniffing traffic to the
  VNC server.","Run the session over an encrypted channel provided by IPsec [RFC4301] or SSH [RFC4254].
  Some VNC server vendors are also providing more secure Security Types within their products.","","","
Details:
VNC Server Unencrypted Data Transmission
(OID: 1.3.6.1.4.1.25623.1.0.108529)
Version used: 2023-07-12T05:05:04Z
","","","",""
192.168.1.29,,23,tcp,4.8,Medium,70,"Mitigation","Telnet Unencrypted Cleartext Login","The remote host is running a Telnet service that allows cleartext logins over
  unencrypted connections.","Vulnerability was detected according to the Vulnerability Detection Method.",1.3.6.1.4.1.25623.1.0.108522,"",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,3a98c51e-f566-426a-b217-b0be31a69409,"An attacker can uncover login names and passwords by sniffing traffic to the
  Telnet service.","Replace Telnet with a protocol like SSH which supports encrypted connections.","","","
Details:
Telnet Unencrypted Cleartext Login
(OID: 1.3.6.1.4.1.25623.1.0.108522)
Version used: 2023-10-13T05:06:09Z
","","","",""
192.168.1.29,,2121,tcp,4.8,Medium,70,"Mitigation","FTP Unencrypted Cleartext Login","The remote host is running a FTP service that allows cleartext logins over
  unencrypted connections.","The remote FTP service accepts logins without a previous sent 'AUTH TLS' command. Response(s):

Non-anonymous sessions: 331 Password required for openvasvt
Anonymous sessions:     331 Password required for anonymous
",1.3.6.1.4.1.25623.1.0.108528,"",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,87e836c4-c548-4309-a4e8-061becced509,"An attacker can uncover login names and passwords by sniffing traffic to the
  FTP service.","Enable FTPS or enforce the connection via the 'AUTH TLS' command. Please see
  the manual of the FTP service for more information.","","","Tries to login to a non FTPS enabled FTP service without sending a
  'AUTH TLS' command first and checks if the service is accepting the login without enforcing the use of
  the 'AUTH TLS' command.
Details:
FTP Unencrypted Cleartext Login
(OID: 1.3.6.1.4.1.25623.1.0.108528)
Version used: 2023-12-20T05:05:58Z
","","","",""
192.168.1.29,,21,tcp,4.8,Medium,70,"Mitigation","FTP Unencrypted Cleartext Login","The remote host is running a FTP service that allows cleartext logins over
  unencrypted connections.","The remote FTP service accepts logins without a previous sent 'AUTH TLS' command. Response(s):

Non-anonymous sessions: 331 Please specify the password.
Anonymous sessions:     331 Please specify the password.
",1.3.6.1.4.1.25623.1.0.108528,"",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,470af3db-aa72-4e1e-9ee8-ea13bc1df8df,"An attacker can uncover login names and passwords by sniffing traffic to the
  FTP service.","Enable FTPS or enforce the connection via the 'AUTH TLS' command. Please see
  the manual of the FTP service for more information.","","","Tries to login to a non FTPS enabled FTP service without sending a
  'AUTH TLS' command first and checks if the service is accepting the login without enforcing the use of
  the 'AUTH TLS' command.
Details:
FTP Unencrypted Cleartext Login
(OID: 1.3.6.1.4.1.25623.1.0.108528)
Version used: 2023-12-20T05:05:58Z
","","","",""
192.168.1.29,,80,tcp,4.8,Medium,80,"Workaround","Cleartext Transmission of Sensitive Information via HTTP","The host / application transmits sensitive information (username, passwords) in
  cleartext via HTTP.","The following input fields were identified (URL:input name):

http://192.168.1.29/dvwa/login.php:password
http://192.168.1.29/phpMyAdmin/:pma_password
http://192.168.1.29/phpMyAdmin/?D=A:pma_password
http://192.168.1.29/tikiwiki/tiki-install.php:pass
http://192.168.1.29/twiki/bin/view/TWiki/TWikiUserAuthentication:oldpassword
",1.3.6.1.4.1.25623.1.0.108440,"",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,4cd66306-ab5f-4545-b883-77cda2a14595,"An attacker could use this situation to compromise or eavesdrop on the
  HTTP communication between the client and the server using a man-in-the-middle attack to get access to
  sensitive data like usernames or passwords.","Enforce the transmission of sensitive data via an encrypted SSL/TLS connection.
  Additionally make sure the host / application is redirecting all users to the secured SSL/TLS connection before
  allowing to input sensitive data into the mentioned functions.","Hosts / applications which doesn't enforce the transmission of sensitive data via an
  encrypted SSL/TLS connection.","","Evaluate previous collected information and check if the host / application is not
  enforcing the transmission of sensitive data via an encrypted SSL/TLS connection.

  The script is currently checking the following:

  - HTTP Basic Authentication (Basic Auth)

  - HTTP Forms (e.g. Login) with input field of type 'password'
Details:
Cleartext Transmission of Sensitive Information via HTTP
(OID: 1.3.6.1.4.1.25623.1.0.108440)
Version used: 2023-09-07T05:05:21Z
","","","",""
192.168.1.29,,5432,tcp,4.3,Medium,98,"Mitigation","SSL/TLS: Deprecated TLSv1.0 and TLSv1.1 Protocol Detection","It was possible to detect the usage of the deprecated TLSv1.0
  and/or TLSv1.1 protocol on this system.","The service is only providing the deprecated TLSv1.0 protocol and supports one or more ciphers. Those supported ciphers can be found in the 'SSL/TLS: Report Supported Cipher Suites' (OID: 1.3.6.1.4.1.25623.1.0.802067) VT.
",1.3.6.1.4.1.25623.1.0.117274,"CVE-2011-3389,CVE-2015-0204",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,f63a5326-7320-42be-9891-8b13c0ca82e3,"An attacker might be able to use the known cryptographic flaws
  to eavesdrop the connection between clients and the service to get access to sensitive data
  transferred within the secured connection.

  Furthermore newly uncovered vulnerabilities in this protocols won't receive security updates
  anymore.","It is recommended to disable the deprecated TLSv1.0 and/or
  TLSv1.1 protocols in favor of the TLSv1.2+ protocols. Please see the references for more
  information.","All services providing an encrypted communication using the
  TLSv1.0 and/or TLSv1.1 protocols.","The TLSv1.0 and TLSv1.1 protocols contain known cryptographic
  flaws like:

  - CVE-2011-3389: Browser Exploit Against SSL/TLS (BEAST)

  - CVE-2015-0204: Factoring Attack on RSA-EXPORT Keys Padding Oracle On Downgraded Legacy
  Encryption (FREAK)","Check the used TLS protocols of the services provided by this
  system.
Details:
SSL/TLS: Deprecated TLSv1.0 and TLSv1.1 Protocol Detection
(OID: 1.3.6.1.4.1.25623.1.0.117274)
Version used: 2023-10-20T16:09:12Z
","","","DFN-CERT-2020-0177,DFN-CERT-2020-0111,DFN-CERT-2019-0068,DFN-CERT-2018-1441,DFN-CERT-2018-1408,DFN-CERT-2016-1372,DFN-CERT-2016-1164,DFN-CERT-2016-0388,DFN-CERT-2015-1853,DFN-CERT-2015-1332,DFN-CERT-2015-0884,DFN-CERT-2015-0800,DFN-CERT-2015-0758,DFN-CERT-2015-0567,DFN-CERT-2015-0544,DFN-CERT-2015-0530,DFN-CERT-2015-0396,DFN-CERT-2015-0375,DFN-CERT-2015-0374,DFN-CERT-2015-0305,DFN-CERT-2015-0199,DFN-CERT-2015-0079,DFN-CERT-2015-0021,DFN-CERT-2014-1414,DFN-CERT-2013-1847,DFN-CERT-2013-1792,DFN-CERT-2012-1979,DFN-CERT-2012-1829,DFN-CERT-2012-1530,DFN-CERT-2012-1380,DFN-CERT-2012-1377,DFN-CERT-2012-1292,DFN-CERT-2012-1214,DFN-CERT-2012-1213,DFN-CERT-2012-1180,DFN-CERT-2012-1156,DFN-CERT-2012-1155,DFN-CERT-2012-1039,DFN-CERT-2012-0956,DFN-CERT-2012-0908,DFN-CERT-2012-0868,DFN-CERT-2012-0867,DFN-CERT-2012-0848,DFN-CERT-2012-0838,DFN-CERT-2012-0776,DFN-CERT-2012-0722,DFN-CERT-2012-0638,DFN-CERT-2012-0627,DFN-CERT-2012-0451,DFN-CERT-2012-0418,DFN-CERT-2012-0354,DFN-CERT-2012-0234,DFN-CERT-2012-0221,DFN-CERT-2012-0177,DFN-CERT-2012-0170,DFN-CERT-2012-0146,DFN-CERT-2012-0142,DFN-CERT-2012-0126,DFN-CERT-2012-0123,DFN-CERT-2012-0095,DFN-CERT-2012-0051,DFN-CERT-2012-0047,DFN-CERT-2012-0021,DFN-CERT-2011-1953,DFN-CERT-2011-1946,DFN-CERT-2011-1844,DFN-CERT-2011-1826,DFN-CERT-2011-1774,DFN-CERT-2011-1743,DFN-CERT-2011-1738,DFN-CERT-2011-1706,DFN-CERT-2011-1628,DFN-CERT-2011-1627,DFN-CERT-2011-1619,DFN-CERT-2011-1482,WID-SEC-2023-1435,CB-K18/0799,CB-K16/1289,CB-K16/1096,CB-K15/1751,CB-K15/1266,CB-K15/0850,CB-K15/0764,CB-K15/0720,CB-K15/0548,CB-K15/0526,CB-K15/0509,CB-K15/0493,CB-K15/0384,CB-K15/0365,CB-K15/0364,CB-K15/0302,CB-K15/0192,CB-K15/0079,CB-K15/0016,CB-K14/1342,CB-K14/0231,CB-K13/0845,CB-K13/0796,CB-K13/0790",""
192.168.1.29,,80,tcp,4.3,Medium,99,"VendorFix","Apache HTTP Server httpOnly Cookie Information Disclosure Vulnerability","Apache HTTP Server is prone to a cookie information disclosure vulnerability.","Vulnerability was detected according to the Vulnerability Detection Method.",1.3.6.1.4.1.25623.1.0.902830,"CVE-2012-0053",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,29cafa2f-5246-4bc9-b3e5-c343a8bb065b,"Successful exploitation will allow attackers to obtain sensitive information
  that may aid in further attacks.","Update to Apache HTTP Server version 2.2.22 or later.","Apache HTTP Server versions 2.2.0 through 2.2.21.","The flaw is due to an error within the default error response for
  status code 400 when no custom ErrorDocument is configured, which can be
  exploited to expose 'httpOnly' cookies.","
Details:
Apache HTTP Server 'httpOnly' Cookie Information Disclosure Vulnerability
(OID: 1.3.6.1.4.1.25623.1.0.902830)
Version used: 2022-04-27T12:01:52Z
","Product: cpe:/a:apache:http_server:2.2.8
Method: Apache HTTP Server Detection Consolidation
(OID: 1.3.6.1.4.1.25623.1.0.117232)
","","DFN-CERT-2015-0082,DFN-CERT-2014-1592,DFN-CERT-2014-0635,DFN-CERT-2013-1307,DFN-CERT-2012-1276,DFN-CERT-2012-1112,DFN-CERT-2012-0928,DFN-CERT-2012-0758,DFN-CERT-2012-0744,DFN-CERT-2012-0568,DFN-CERT-2012-0425,DFN-CERT-2012-0424,DFN-CERT-2012-0387,DFN-CERT-2012-0343,DFN-CERT-2012-0332,DFN-CERT-2012-0306,DFN-CERT-2012-0264,DFN-CERT-2012-0203,DFN-CERT-2012-0188,CB-K15/0080,CB-K14/1505,CB-K14/0608",""
192.168.1.29,,80,tcp,4.3,Medium,99,"WillNotFix","phpMyAdmin error.php Cross Site Scripting Vulnerability","phpMyAdmin is prone to a cross-site scripting (XSS) vulnerability.","Vulnerability was detected according to the Vulnerability Detection Method.",1.3.6.1.4.1.25623.1.0.801660,"CVE-2010-4480",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,5f33dae6-1038-46c4-af2d-8c8b67a3de50,"Successful exploitation will allow attackers to inject arbitrary
HTML code within the error page and conduct phishing attacks.","No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.","phpMyAdmin version 3.3.8.1 and prior.","The flaw is caused by input validation errors in the 'error.php'
script when processing crafted BBcode tags containing '@' characters, which
could allow attackers to inject arbitrary HTML code within the error page
and conduct phishing attacks.","
Details:
phpMyAdmin 'error.php' Cross Site Scripting Vulnerability
(OID: 1.3.6.1.4.1.25623.1.0.801660)
Version used: 2023-10-17T05:05:34Z
","","","DFN-CERT-2011-0467,DFN-CERT-2011-0451,DFN-CERT-2011-0016,DFN-CERT-2011-0002",""
192.168.1.29,,80,tcp,4.3,Medium,80,"VendorFix","jQuery < 1.6.3 XSS Vulnerability","jQuery is prone to a cross-site scripting (XSS)
  vulnerability.","Installed version: 1.3.2
Fixed version:     1.6.3
Installation
path / port:       /mutillidae/javascript/ddsmoothmenu/jquery.min.js

Detection info (see OID: 1.3.6.1.4.1.25623.1.0.150658 for more info):
- Identified file: http://192.168.1.29/mutillidae/javascript/ddsmoothmenu/jquery.min.js
- Referenced at:   http://192.168.1.29/mutillidae/
",1.3.6.1.4.1.25623.1.0.141637,"CVE-2011-4969",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,8283eaed-dc81-45f7-9318-31a9900309c9,"","Update to version 1.6.3 or later.","jQuery prior to version 1.6.3.","Cross-site scripting (XSS) vulnerability in jQuery before 1.6.3,
  when using location.hash to select elements, allows remote attackers to inject arbitrary web
  script or HTML via a crafted tag.","Checks if a vulnerable version is present on the target host.
Details:
jQuery < 1.6.3 XSS Vulnerability
(OID: 1.3.6.1.4.1.25623.1.0.141637)
Version used: 2023-07-14T05:06:08Z
","","","DFN-CERT-2017-0199,DFN-CERT-2016-0890,CB-K17/0195",""
192.168.1.29,,22,tcp,4.3,Medium,80,"Mitigation","Weak Encryption Algorithm(s) Supported (SSH)","The remote SSH server is configured to allow / support weak
  encryption algorithm(s).","The remote SSH server supports the following weak client-to-server encryption algorithm(s):

3des-cbc
aes128-cbc
aes192-cbc
aes256-cbc
arcfour
arcfour128
arcfour256
blowfish-cbc
cast128-cbc
rijndael-cbc@lysator.liu.se


The remote SSH server supports the following weak server-to-client encryption algorithm(s):

3des-cbc
aes128-cbc
aes192-cbc
aes256-cbc
arcfour
arcfour128
arcfour256
blowfish-cbc
cast128-cbc
rijndael-cbc@lysator.liu.se
",1.3.6.1.4.1.25623.1.0.105611,"",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,96b99f76-8456-439a-b43f-3e3324847be8,"","Disable the reported weak encryption algorithm(s).","","'- The 'arcfour' cipher is the Arcfour stream cipher with 128-bit
  keys. The Arcfour cipher is believed to be compatible with the RC4 cipher [SCHNEIER]. Arcfour
  (and RC4) has problems with weak keys, and should not be used anymore.

  - The 'none' algorithm specifies that no encryption is to be done. Note that this method provides
  no confidentiality protection, and it is NOT RECOMMENDED to use it.

  - A vulnerability exists in SSH messages that employ CBC mode that may allow an attacker to
  recover plaintext from a block of ciphertext.","Checks the supported encryption algorithms (client-to-server
  and server-to-client) of the remote SSH server.

  Currently weak encryption algorithms are defined as the following:

  - Arcfour (RC4) cipher based algorithms

  - 'none' algorithm

  - CBC mode cipher based algorithms
Details:
Weak Encryption Algorithm(s) Supported (SSH)
(OID: 1.3.6.1.4.1.25623.1.0.105611)
Version used: 2023-10-12T05:05:32Z
","","","",""
192.168.1.29,,25,tcp,4.3,Medium,98,"Mitigation","SSL/TLS: Deprecated TLSv1.0 and TLSv1.1 Protocol Detection","It was possible to detect the usage of the deprecated TLSv1.0
  and/or TLSv1.1 protocol on this system.","The service is only providing the deprecated TLSv1.0 protocol and supports one or more ciphers. Those supported ciphers can be found in the 'SSL/TLS: Report Supported Cipher Suites' (OID: 1.3.6.1.4.1.25623.1.0.802067) VT.
",1.3.6.1.4.1.25623.1.0.117274,"CVE-2011-3389,CVE-2015-0204",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,3389e7e5-6e6a-4384-ade6-9f2a850150ba,"An attacker might be able to use the known cryptographic flaws
  to eavesdrop the connection between clients and the service to get access to sensitive data
  transferred within the secured connection.

  Furthermore newly uncovered vulnerabilities in this protocols won't receive security updates
  anymore.","It is recommended to disable the deprecated TLSv1.0 and/or
  TLSv1.1 protocols in favor of the TLSv1.2+ protocols. Please see the references for more
  information.","All services providing an encrypted communication using the
  TLSv1.0 and/or TLSv1.1 protocols.","The TLSv1.0 and TLSv1.1 protocols contain known cryptographic
  flaws like:

  - CVE-2011-3389: Browser Exploit Against SSL/TLS (BEAST)

  - CVE-2015-0204: Factoring Attack on RSA-EXPORT Keys Padding Oracle On Downgraded Legacy
  Encryption (FREAK)","Check the used TLS protocols of the services provided by this
  system.
Details:
SSL/TLS: Deprecated TLSv1.0 and TLSv1.1 Protocol Detection
(OID: 1.3.6.1.4.1.25623.1.0.117274)
Version used: 2023-10-20T16:09:12Z
","","","DFN-CERT-2020-0177,DFN-CERT-2020-0111,DFN-CERT-2019-0068,DFN-CERT-2018-1441,DFN-CERT-2018-1408,DFN-CERT-2016-1372,DFN-CERT-2016-1164,DFN-CERT-2016-0388,DFN-CERT-2015-1853,DFN-CERT-2015-1332,DFN-CERT-2015-0884,DFN-CERT-2015-0800,DFN-CERT-2015-0758,DFN-CERT-2015-0567,DFN-CERT-2015-0544,DFN-CERT-2015-0530,DFN-CERT-2015-0396,DFN-CERT-2015-0375,DFN-CERT-2015-0374,DFN-CERT-2015-0305,DFN-CERT-2015-0199,DFN-CERT-2015-0079,DFN-CERT-2015-0021,DFN-CERT-2014-1414,DFN-CERT-2013-1847,DFN-CERT-2013-1792,DFN-CERT-2012-1979,DFN-CERT-2012-1829,DFN-CERT-2012-1530,DFN-CERT-2012-1380,DFN-CERT-2012-1377,DFN-CERT-2012-1292,DFN-CERT-2012-1214,DFN-CERT-2012-1213,DFN-CERT-2012-1180,DFN-CERT-2012-1156,DFN-CERT-2012-1155,DFN-CERT-2012-1039,DFN-CERT-2012-0956,DFN-CERT-2012-0908,DFN-CERT-2012-0868,DFN-CERT-2012-0867,DFN-CERT-2012-0848,DFN-CERT-2012-0838,DFN-CERT-2012-0776,DFN-CERT-2012-0722,DFN-CERT-2012-0638,DFN-CERT-2012-0627,DFN-CERT-2012-0451,DFN-CERT-2012-0418,DFN-CERT-2012-0354,DFN-CERT-2012-0234,DFN-CERT-2012-0221,DFN-CERT-2012-0177,DFN-CERT-2012-0170,DFN-CERT-2012-0146,DFN-CERT-2012-0142,DFN-CERT-2012-0126,DFN-CERT-2012-0123,DFN-CERT-2012-0095,DFN-CERT-2012-0051,DFN-CERT-2012-0047,DFN-CERT-2012-0021,DFN-CERT-2011-1953,DFN-CERT-2011-1946,DFN-CERT-2011-1844,DFN-CERT-2011-1826,DFN-CERT-2011-1774,DFN-CERT-2011-1743,DFN-CERT-2011-1738,DFN-CERT-2011-1706,DFN-CERT-2011-1628,DFN-CERT-2011-1627,DFN-CERT-2011-1619,DFN-CERT-2011-1482,WID-SEC-2023-1435,CB-K18/0799,CB-K16/1289,CB-K16/1096,CB-K15/1751,CB-K15/1266,CB-K15/0850,CB-K15/0764,CB-K15/0720,CB-K15/0548,CB-K15/0526,CB-K15/0509,CB-K15/0493,CB-K15/0384,CB-K15/0365,CB-K15/0364,CB-K15/0302,CB-K15/0192,CB-K15/0079,CB-K15/0016,CB-K14/1342,CB-K14/0231,CB-K13/0845,CB-K13/0796,CB-K13/0790",""
192.168.1.29,,25,tcp,4.3,Medium,80,"VendorFix","SSL/TLS: RSA Temporary Key Handling RSA_EXPORT Downgrade Issue (FREAK)","This host is accepting 'RSA_EXPORT' cipher suites
  and is prone to man in the middle attack.","'RSA_EXPORT' cipher suites accepted by this service via the SSLv3 protocol:

TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
TLS_RSA_EXPORT_WITH_RC4_40_MD5

'RSA_EXPORT' cipher suites accepted by this service via the TLSv1.0 protocol:

TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
TLS_RSA_EXPORT_WITH_RC4_40_MD5


",1.3.6.1.4.1.25623.1.0.805142,"CVE-2015-0204",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,3d2d2b39-7ab0-4a6c-a04b-2085ae452fa6,"Successful exploitation will allow remote
  attacker to downgrade the security of a session to use 'RSA_EXPORT' cipher suites,
  which are significantly weaker than non-export cipher suites. This may allow a
  man-in-the-middle attacker to more easily break the encryption and monitor
  or tamper with the encrypted stream.","'- Remove support for 'RSA_EXPORT' cipher
  suites from the service.

  - If running OpenSSL update to version 0.9.8zd or 1.0.0p
  or 1.0.1k or later.","'- Hosts accepting 'RSA_EXPORT' cipher suites

  - OpenSSL version before 0.9.8zd, 1.0.0 before 1.0.0p, and 1.0.1 before 1.0.1k.","Flaw is due to improper handling RSA
  temporary keys in a non-export RSA key exchange cipher suite.","Check previous collected cipher suites saved in the KB.
Details:
SSL/TLS: RSA Temporary Key Handling 'RSA_EXPORT' Downgrade Issue (FREAK)
(OID: 1.3.6.1.4.1.25623.1.0.805142)
Version used: 2023-07-25T05:05:58Z
","","","DFN-CERT-2018-1408,DFN-CERT-2016-1372,DFN-CERT-2016-1164,DFN-CERT-2016-0388,DFN-CERT-2015-1853,DFN-CERT-2015-1332,DFN-CERT-2015-0884,DFN-CERT-2015-0800,DFN-CERT-2015-0758,DFN-CERT-2015-0567,DFN-CERT-2015-0544,DFN-CERT-2015-0530,DFN-CERT-2015-0396,DFN-CERT-2015-0375,DFN-CERT-2015-0374,DFN-CERT-2015-0305,DFN-CERT-2015-0199,DFN-CERT-2015-0021,CB-K18/0799,CB-K16/1289,CB-K16/1096,CB-K15/1751,CB-K15/1266,CB-K15/0850,CB-K15/0764,CB-K15/0720,CB-K15/0548,CB-K15/0526,CB-K15/0509,CB-K15/0493,CB-K15/0384,CB-K15/0365,CB-K15/0364,CB-K15/0302,CB-K15/0192,CB-K15/0016",""
192.168.1.29,,5432,tcp,4.0,Medium,80,"Workaround","SSL/TLS: Diffie-Hellman Key Exchange Insufficient DH Group Strength Vulnerability","The SSL/TLS service uses Diffie-Hellman groups with insufficient strength
  (key size < 2048).","Server Temporary Key Size: 1024 bits

",1.3.6.1.4.1.25623.1.0.106223,"",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,eb40b3a6-557b-4c38-bc51-9016ecffa279,"An attacker might be able to decrypt the SSL/TLS communication offline.","Deploy (Ephemeral) Elliptic-Curve Diffie-Hellman (ECDHE) or use
  a 2048-bit or stronger Diffie-Hellman group (see the references).

  For Apache Web Servers:
  Beginning with version 2.4.7, mod_ssl will use DH parameters which include primes with lengths of more than 1024 bits.","","The Diffie-Hellman group are some big numbers that are used as base for
  the DH computations. They can be, and often are, fixed. The security of the final secret depends on the size
  of these parameters. It was found that 512 and 768 bits to be weak, 1024 bits to be breakable by really
  powerful attackers like governments.","Checks the DHE temporary public key size.
Details:
SSL/TLS: Diffie-Hellman Key Exchange Insufficient DH Group Strength Vulnerab...
(OID: 1.3.6.1.4.1.25623.1.0.106223)
Version used: 2023-07-21T05:05:22Z
","","","",""
192.168.1.29,,25,tcp,4.0,Medium,80,"Workaround","SSL/TLS: Diffie-Hellman Key Exchange Insufficient DH Group Strength Vulnerability","The SSL/TLS service uses Diffie-Hellman groups with insufficient strength
  (key size < 2048).","Server Temporary Key Size: 1024 bits

",1.3.6.1.4.1.25623.1.0.106223,"",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,00aec6b1-ce59-4aae-a1a7-202e9041bb4f,"An attacker might be able to decrypt the SSL/TLS communication offline.","Deploy (Ephemeral) Elliptic-Curve Diffie-Hellman (ECDHE) or use
  a 2048-bit or stronger Diffie-Hellman group (see the references).

  For Apache Web Servers:
  Beginning with version 2.4.7, mod_ssl will use DH parameters which include primes with lengths of more than 1024 bits.","","The Diffie-Hellman group are some big numbers that are used as base for
  the DH computations. They can be, and often are, fixed. The security of the final secret depends on the size
  of these parameters. It was found that 512 and 768 bits to be weak, 1024 bits to be breakable by really
  powerful attackers like governments.","Checks the DHE temporary public key size.
Details:
SSL/TLS: Diffie-Hellman Key Exchange Insufficient DH Group Strength Vulnerab...
(OID: 1.3.6.1.4.1.25623.1.0.106223)
Version used: 2023-07-21T05:05:22Z
","","","",""
192.168.1.29,,5432,tcp,4.0,Medium,80,"Mitigation","SSL/TLS: Certificate Signed Using A Weak Signature Algorithm","The remote service is using a SSL/TLS certificate in the certificate chain that has been signed using a
  cryptographically weak hashing algorithm.","The following certificates are part of the certificate chain but using insecure signature algorithms:

Subject:              1.2.840.113549.1.9.1=#726F6F74407562756E74753830342D626173652E6C6F63616C646F6D61696E,CN=ubuntu804-base.localdomain,OU=Office for Complication of Otherwise Simple Affairs,O=OCOSA,L=Everywhere,ST=There is no such thing outside US,C=XX
Signature Algorithm:  sha1WithRSAEncryption


",1.3.6.1.4.1.25623.1.0.105880,"",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,9a96a6a7-caeb-43fc-bee2-1a4f0b89e1d6,"","Servers that use SSL/TLS certificates signed with a weak SHA-1, MD5, MD4 or MD2 hashing algorithm will need to obtain new
  SHA-2 signed SSL/TLS certificates to avoid web browser SSL/TLS certificate warnings.","","The following hashing algorithms used for signing SSL/TLS certificates are considered cryptographically weak
  and not secure enough for ongoing use:

  - Secure Hash Algorithm 1 (SHA-1)

  - Message Digest 5 (MD5)

  - Message Digest 4 (MD4)

  - Message Digest 2 (MD2)

  Beginning as late as January 2017 and as early as June 2016, browser developers such as Microsoft and Google will begin warning users when visiting
  web sites that use SHA-1 signed Secure Socket Layer (SSL) certificates.

  NOTE: The script preference allows to set one or more custom SHA-1 fingerprints of CA certificates which are trusted by this routine. The fingerprints
  needs to be passed comma-separated and case-insensitive:

  Fingerprint1

  or

  fingerprint1, Fingerprint2","Check which hashing algorithm was used to sign the remote SSL/TLS certificate.
Details:
SSL/TLS: Certificate Signed Using A Weak Signature Algorithm
(OID: 1.3.6.1.4.1.25623.1.0.105880)
Version used: 2021-10-15T11:13:32Z
","","","",""
192.168.1.29,,25,tcp,4.0,Medium,80,"Mitigation","SSL/TLS: Certificate Signed Using A Weak Signature Algorithm","The remote service is using a SSL/TLS certificate in the certificate chain that has been signed using a
  cryptographically weak hashing algorithm.","The following certificates are part of the certificate chain but using insecure signature algorithms:

Subject:              1.2.840.113549.1.9.1=#726F6F74407562756E74753830342D626173652E6C6F63616C646F6D61696E,CN=ubuntu804-base.localdomain,OU=Office for Complication of Otherwise Simple Affairs,O=OCOSA,L=Everywhere,ST=There is no such thing outside US,C=XX
Signature Algorithm:  sha1WithRSAEncryption


",1.3.6.1.4.1.25623.1.0.105880,"",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,7cba656a-2b5e-4249-aa75-ff52b288cf56,"","Servers that use SSL/TLS certificates signed with a weak SHA-1, MD5, MD4 or MD2 hashing algorithm will need to obtain new
  SHA-2 signed SSL/TLS certificates to avoid web browser SSL/TLS certificate warnings.","","The following hashing algorithms used for signing SSL/TLS certificates are considered cryptographically weak
  and not secure enough for ongoing use:

  - Secure Hash Algorithm 1 (SHA-1)

  - Message Digest 5 (MD5)

  - Message Digest 4 (MD4)

  - Message Digest 2 (MD2)

  Beginning as late as January 2017 and as early as June 2016, browser developers such as Microsoft and Google will begin warning users when visiting
  web sites that use SHA-1 signed Secure Socket Layer (SSL) certificates.

  NOTE: The script preference allows to set one or more custom SHA-1 fingerprints of CA certificates which are trusted by this routine. The fingerprints
  needs to be passed comma-separated and case-insensitive:

  Fingerprint1

  or

  fingerprint1, Fingerprint2","Check which hashing algorithm was used to sign the remote SSL/TLS certificate.
Details:
SSL/TLS: Certificate Signed Using A Weak Signature Algorithm
(OID: 1.3.6.1.4.1.25623.1.0.105880)
Version used: 2021-10-15T11:13:32Z
","","","",""
192.168.1.29,,25,tcp,3.7,Low,80,"VendorFix","SSL/TLS: DHE_EXPORT Man in the Middle Security Bypass Vulnerability (LogJam)","This host is accepting 'DHE_EXPORT' cipher suites
  and is prone to man in the middle attack.","'DHE_EXPORT' cipher suites accepted by this service via the SSLv3 protocol:

TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA
TLS_DH_anon_EXPORT_WITH_RC4_40_MD5

'DHE_EXPORT' cipher suites accepted by this service via the TLSv1.0 protocol:

TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA
TLS_DH_anon_EXPORT_WITH_RC4_40_MD5


",1.3.6.1.4.1.25623.1.0.805188,"CVE-2015-4000",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,3bc437d5-3205-4bd5-897b-2e81db7b99f0,"Successful exploitation will allow a
  man-in-the-middle attacker to downgrade the security of a TLS session to
  512-bit export-grade cryptography, which is significantly weaker, allowing
  the attacker to more easily break the encryption and monitor or tamper with
  the encrypted stream.","'- Remove support for 'DHE_EXPORT' cipher
  suites from the service

  - If running OpenSSL updateto version 1.0.2b or 1.0.1n or later.","'- Hosts accepting 'DHE_EXPORT' cipher suites

  - OpenSSL version before 1.0.2b and 1.0.1n","Flaw is triggered when handling
  Diffie-Hellman key exchanges defined in the 'DHE_EXPORT' cipher suites.","Check previous collected cipher suites saved in the KB.
Details:
SSL/TLS: 'DHE_EXPORT' Man in the Middle Security Bypass Vulnerability (LogJa...
(OID: 1.3.6.1.4.1.25623.1.0.805188)
Version used: 2023-07-25T05:05:58Z
","","","DFN-CERT-2023-2939,DFN-CERT-2021-0775,DFN-CERT-2020-1561,DFN-CERT-2020-1276,DFN-CERT-2016-1692,DFN-CERT-2016-1648,DFN-CERT-2016-0665,DFN-CERT-2016-0642,DFN-CERT-2016-0184,DFN-CERT-2016-0135,DFN-CERT-2016-0101,DFN-CERT-2016-0035,DFN-CERT-2015-1679,DFN-CERT-2015-1632,DFN-CERT-2015-1608,DFN-CERT-2015-1542,DFN-CERT-2015-1518,DFN-CERT-2015-1406,DFN-CERT-2015-1341,DFN-CERT-2015-1194,DFN-CERT-2015-1144,DFN-CERT-2015-1113,DFN-CERT-2015-1078,DFN-CERT-2015-1067,DFN-CERT-2015-1016,DFN-CERT-2015-0980,DFN-CERT-2015-0977,DFN-CERT-2015-0976,DFN-CERT-2015-0960,DFN-CERT-2015-0956,DFN-CERT-2015-0944,DFN-CERT-2015-0925,DFN-CERT-2015-0879,DFN-CERT-2015-0844,DFN-CERT-2015-0737,CB-K21/0067,CB-K19/0812,CB-K16/1593,CB-K16/1552,CB-K16/0617,CB-K16/0599,CB-K16/0168,CB-K16/0121,CB-K16/0090,CB-K16/0030,CB-K15/1591,CB-K15/1550,CB-K15/1517,CB-K15/1464,CB-K15/1442,CB-K15/1334,CB-K15/1269,CB-K15/1136,CB-K15/1090,CB-K15/1059,CB-K15/1022,CB-K15/1015,CB-K15/0964,CB-K15/0932,CB-K15/0927,CB-K15/0926,CB-K15/0907,CB-K15/0901,CB-K15/0896,CB-K15/0877,CB-K15/0834,CB-K15/0802,CB-K15/0733",""
192.168.1.29,,5432,tcp,3.4,Low,80,"Mitigation","SSL/TLS: SSLv3 Protocol CBC Cipher Suites Information Disclosure Vulnerability (POODLE)","This host is prone to an information disclosure vulnerability.","Vulnerability was detected according to the Vulnerability Detection Method.",1.3.6.1.4.1.25623.1.0.802087,"CVE-2014-3566",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,b8110ff0-35c9-43b4-b417-3ae2927ec217,"Successful exploitation will allow a  man-in-the-middle attackers gain access to the plain text data stream.","Possible Mitigations are:

  - Disable SSLv3

  - Disable cipher suites supporting CBC cipher modes

  - Enable TLS_FALLBACK_SCSV if the service is providing TLSv1.0+","","The flaw is due to the block cipher padding not being deterministic and not covered by the Message Authentication Code","Evaluate previous collected information about this service.
Details:
SSL/TLS: SSLv3 Protocol CBC Cipher Suites Information Disclosure Vulnerabili...
(OID: 1.3.6.1.4.1.25623.1.0.802087)
Version used: 2023-07-26T05:05:09Z
","","","DFN-CERT-2017-1238,DFN-CERT-2017-1236,DFN-CERT-2016-1929,DFN-CERT-2016-1527,DFN-CERT-2016-1468,DFN-CERT-2016-1168,DFN-CERT-2016-0884,DFN-CERT-2016-0642,DFN-CERT-2016-0388,DFN-CERT-2016-0171,DFN-CERT-2015-1431,DFN-CERT-2015-1075,DFN-CERT-2015-1026,DFN-CERT-2015-0664,DFN-CERT-2015-0548,DFN-CERT-2015-0404,DFN-CERT-2015-0396,DFN-CERT-2015-0259,DFN-CERT-2015-0254,DFN-CERT-2015-0245,DFN-CERT-2015-0118,DFN-CERT-2015-0114,DFN-CERT-2015-0083,DFN-CERT-2015-0082,DFN-CERT-2015-0081,DFN-CERT-2015-0076,DFN-CERT-2014-1717,DFN-CERT-2014-1680,DFN-CERT-2014-1632,DFN-CERT-2014-1564,DFN-CERT-2014-1542,DFN-CERT-2014-1414,DFN-CERT-2014-1366,DFN-CERT-2014-1354,WID-SEC-2023-0431,CB-K17/1198,CB-K17/1196,CB-K16/1828,CB-K16/1438,CB-K16/1384,CB-K16/1102,CB-K16/0599,CB-K16/0156,CB-K15/1514,CB-K15/1358,CB-K15/1021,CB-K15/0972,CB-K15/0637,CB-K15/0590,CB-K15/0525,CB-K15/0393,CB-K15/0384,CB-K15/0287,CB-K15/0252,CB-K15/0246,CB-K15/0237,CB-K15/0118,CB-K15/0110,CB-K15/0108,CB-K15/0080,CB-K15/0078,CB-K15/0077,CB-K15/0075,CB-K14/1617,CB-K14/1581,CB-K14/1537,CB-K14/1479,CB-K14/1458,CB-K14/1342,CB-K14/1314,CB-K14/1313,CB-K14/1311,CB-K14/1304,CB-K14/1296",""
192.168.1.29,,25,tcp,3.4,Low,80,"Mitigation","SSL/TLS: SSLv3 Protocol CBC Cipher Suites Information Disclosure Vulnerability (POODLE)","This host is prone to an information disclosure vulnerability.","Vulnerability was detected according to the Vulnerability Detection Method.",1.3.6.1.4.1.25623.1.0.802087,"CVE-2014-3566",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,3719fad1-7d84-46b3-8916-4f9521611365,"Successful exploitation will allow a  man-in-the-middle attackers gain access to the plain text data stream.","Possible Mitigations are:

  - Disable SSLv3

  - Disable cipher suites supporting CBC cipher modes

  - Enable TLS_FALLBACK_SCSV if the service is providing TLSv1.0+","","The flaw is due to the block cipher padding not being deterministic and not covered by the Message Authentication Code","Evaluate previous collected information about this service.
Details:
SSL/TLS: SSLv3 Protocol CBC Cipher Suites Information Disclosure Vulnerabili...
(OID: 1.3.6.1.4.1.25623.1.0.802087)
Version used: 2023-07-26T05:05:09Z
","","","DFN-CERT-2017-1238,DFN-CERT-2017-1236,DFN-CERT-2016-1929,DFN-CERT-2016-1527,DFN-CERT-2016-1468,DFN-CERT-2016-1168,DFN-CERT-2016-0884,DFN-CERT-2016-0642,DFN-CERT-2016-0388,DFN-CERT-2016-0171,DFN-CERT-2015-1431,DFN-CERT-2015-1075,DFN-CERT-2015-1026,DFN-CERT-2015-0664,DFN-CERT-2015-0548,DFN-CERT-2015-0404,DFN-CERT-2015-0396,DFN-CERT-2015-0259,DFN-CERT-2015-0254,DFN-CERT-2015-0245,DFN-CERT-2015-0118,DFN-CERT-2015-0114,DFN-CERT-2015-0083,DFN-CERT-2015-0082,DFN-CERT-2015-0081,DFN-CERT-2015-0076,DFN-CERT-2014-1717,DFN-CERT-2014-1680,DFN-CERT-2014-1632,DFN-CERT-2014-1564,DFN-CERT-2014-1542,DFN-CERT-2014-1414,DFN-CERT-2014-1366,DFN-CERT-2014-1354,WID-SEC-2023-0431,CB-K17/1198,CB-K17/1196,CB-K16/1828,CB-K16/1438,CB-K16/1384,CB-K16/1102,CB-K16/0599,CB-K16/0156,CB-K15/1514,CB-K15/1358,CB-K15/1021,CB-K15/0972,CB-K15/0637,CB-K15/0590,CB-K15/0525,CB-K15/0393,CB-K15/0384,CB-K15/0287,CB-K15/0252,CB-K15/0246,CB-K15/0237,CB-K15/0118,CB-K15/0110,CB-K15/0108,CB-K15/0080,CB-K15/0078,CB-K15/0077,CB-K15/0075,CB-K14/1617,CB-K14/1581,CB-K14/1537,CB-K14/1479,CB-K14/1458,CB-K14/1342,CB-K14/1314,CB-K14/1313,CB-K14/1311,CB-K14/1304,CB-K14/1296",""
192.168.1.29,,22,tcp,2.6,Low,80,"Mitigation","Weak MAC Algorithm(s) Supported (SSH)","The remote SSH server is configured to allow / support weak MAC
  algorithm(s).","The remote SSH server supports the following weak client-to-server MAC algorithm(s):

hmac-md5
hmac-md5-96
hmac-sha1-96
umac-64@openssh.com


The remote SSH server supports the following weak server-to-client MAC algorithm(s):

hmac-md5
hmac-md5-96
hmac-sha1-96
umac-64@openssh.com
",1.3.6.1.4.1.25623.1.0.105610,"",9882c23f-e51a-4941-b5d1-3952c31e917e,"Immediate scan of IP 192.168.1.29",2024-05-04T11:37:24+02:00,d844f76d-6c38-47c2-b0c0-ca0f81cda23f,"","Disable the reported weak MAC algorithm(s).","","","Checks the supported MAC algorithms (client-to-server and
  server-to-client) of the remote SSH server.

  Currently weak MAC algorithms are defined as the following:

  - MD5 based algorithms

  - 96-bit based algorithms

  - 64-bit based algorithms

  - 'none' algorithm
Details:
Weak MAC Algorithm(s) Supported (SSH)
(OID: 1.3.6.1.4.1.25623.1.0.105610)
Version used: 2023-10-12T05:05:32Z
","","","",""
"""
scan_results = parse_csv_report(csv_data)
formatted_results = []
for result in scan_results:
    formatted_result = {
        'IP': result['IP'],
        'Port': result['Port'],
        'Protocol': result['Protocol'],
        'Sévérité': result['Sévérité'],
        'NVT': result['NVT'],
        'CVE': result['CVE']
    }
    formatted_results.append(formatted_result)

# Load existing JSON data
with open('Test.json', 'r') as json_file:
    existing_data = json.load(json_file)

# Add the new variable vulnerabilite_detecte
existing_data['vulnerabilite_detecte'] = formatted_results

# Write updated JSON data back to file
with open('Test.json', 'w') as json_file:
    json.dump(existing_data, json_file)