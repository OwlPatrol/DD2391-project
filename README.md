# DD2391-project Group 1 - Log4Shell
## Motivation & Problem Statement
**Overview of Log4Shell**
Log4Shell, discovered in December 2021, is a critical vulnerability in the Apache Log4j library, a widely-used Java-based logging framework. The vulnerability is officially tracked as CVE-2021-44228 and allows for remote code execution (RCE) by exploiting how Log4j handles user-controlled input in log messages. This issue stems from Log4j’s support for Java Naming and Directory Interface (JNDI) lookups in log entries, which could be abused by an attacker to trick Log4j into fetching and executing arbitrary code from remote servers. Given the ubiquity of Log4j in enterprise software, cloud services, and widely-used platforms, the scope of this vulnerability’s impact is immense.

**History and Emergence**
Log4Shell was first disclosed publicly in December 2021, but the issue had likely existed unnoticed for years in Log4j version 2.x, which was introduced in 2013. The vulnerability was uncovered during the usage of Minecraft servers, where attackers quickly demonstrated how easily they could exploit it to gain control over a system by sending a simple chat message containing a malicious string. The fact that such a trivial input could lead to remote code execution across a wide variety of platforms triggered immediate concern, leading to widespread panic among system administrators, cybersecurity experts, and software vendors.

Many high-profile companies and critical infrastructures that rely on Log4j were affected, including Amazon Web Services, Cloudflare, Twitter, and many others, highlighting the pervasive nature of the vulnerability. The vulnerability was particularly dangerous due to how easily attackers could exploit it: simply by sending a crafted string in various inputs such as HTTP requests, chat messages, or any other logged data, they could compromise servers without the need for authentication.

**Severity of the Problem**
Log4Shell is considered one of the most severe vulnerabilities in recent history due to several factors:

1. **Ease of Exploitation**: The vulnerability requires minimal technical expertise to exploit. In most cases, a simple string injected into a log is enough to trigger the vulnerability, giving attackers access to sensitive systems without any user interaction.
2. **Widespread Usage of Log4j**: Log4j is embedded in countless applications and services across the globe. It is used by enterprises, cloud platforms, and third-party services, making the vulnerability’s reach vast and affecting millions of systems. Many organizations were unaware that they even had Log4j integrated, leading to challenges in identifying and patching affected systems.
3. **Potential for Remote Code Execution**: Once exploited, attackers can achieve RCE, allowing them to execute arbitrary code on the target machine. This means attackers can take full control of a vulnerable system, steal data, deploy ransomware, or even create backdoors for persistent access.
4. **Global Impact**: Log4Shell created a global race among security professionals to patch systems, while malicious actors hurried to exploit the vulnerability. Major government agencies, cybersecurity firms, and enterprises worldwide raised alarms, leading to an unprecedented effort to protect vulnerable systems.
Given these factors, Log4Shell was assigned the highest severity score—10 out of 10—on the CVSS (Common Vulnerability Scoring System) scale.

**Problem Statement**
Our project focuses on understanding, detecting, and mitigating the Log4Shell vulnerability. By reimplementing the weakness, we gain a deep understanding of the exploit's mechanics and evaluate real-world scenarios where this vulnerability could be leveraged. The project aims to:

1. **Understand**: We aim to dissect the underlying issue in Log4j, exploring how the JNDI lookup feature can be exploited and why it was initially designed to behave in a vulnerable manner.
2. **Detect**: We evaluate current detection methods to identify systems still vulnerable to Log4Shell and determine how security tools can better identify attempts to exploit this weakness. This includes exploring intrusion detection systems (IDS), anomaly detection in logging patterns, and system activity monitoring.
3. **Mitigate**: Several mitigation techniques are explored, from patching affected Log4j versions to disabling vulnerable features (such as JNDI lookups) and enhancing runtime security through network controls and sandboxing. Additionally, we analyze security practices that should be adopted at an organizational level to reduce the chances of such vulnerabilities being exploited in the future.

This project aims to contribute both practical and theoretical insights into how systems can remain protected from such critical weaknesses, ensuring resilience against future exploits of similar nature.

## Referneces
## Documentation of Project 
## Instructions on Testing
### Vulnerable App

Located in `vulnerable-app/`. Install Apache maven (tested on version 3.9.6),
navigate to the app's directory and run the command `mvn compile exec:java -q
-Dexec.mainClass="App"`.

It is a web server that listen on port 8080 and logs the current time, the
connecting clients' IP address and user agent and the requests method and path,
all of which are pretty common for web servers to log.

By default it only listens for connections coming from the host itself. To
listen for connections coming from other hosts (which is pretty dangerous),
append `-Dexec.args="listen-any"` to the command mentioned above.

## Exploit Host

Located in `exploit-host/`. Install Apache maven (tested on version 3.9.6),
navigate to the app's directory and run the command
`mvn package -q && java -cp target/exploit-host-1.0-SNAPSHOT.jar App`.

It by default listens on port 1389 and 3000, but can be changed with
`$LDAP_PORT` and `$HTTP_PORT` respectively. If the client cannot reach the
exploit host through `localhost`, `$HOST` must also be set to the ip or
hostname on which it can.
