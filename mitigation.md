# Methods of Mitigation

## Identifying the Danger
*Describe what the exploit actually does and how it functions*

## The heavy-handed Approach
### Disabling JNDI lookups
The vulnerability is triggered by JNDI lookups in Log4j, which can be disabled to prevent the exploit. This can be done by setting a system property or modifying the configuration to ensure Log4j does not perform lookups.

#### What's JNDI?
The Java Naming and Directory Interface (JNDI) is a Java API that allows Java applications to look up data and objects in a variety of naming and directory services. Essentially, JNDI provides a standardized way for Java programs to access different kinds of naming and directory services, like DNS, LDAP (Lightweight Directory Access Protocol), and RMI (Remote Method Invocation) registries.

#### Through System Setup

Log4j 2.10.0 and later versions provide a system property to disable message lookups globally:
Add the following JVM option to disable the vulnerable lookup feature:

`-Dlog4j2.formatMsgNoLookups=true`

This will disable the `JNDI` lookup mechanism and prevent exploitation through `${jndi:...}` in log messages.

Alternatively, you can disable the lookups by setting the `LOG4J_FORMAT_MSG_NO_LOOKUPS` environment variable to true:


For Linux/macOS:

`export LOG4J_FORMAT_MSG_NO_LOOKUPS=true`

For Windows:

`set LOG4J_FORMAT_MSG_NO_LOOKUPS=true`
This is effective for versions 2.10.0 to 2.14.1 of Log4j. For versions prior to 2.10.0, this approach will not work.

#### Through Removing the JndiLookupClass from the Classpath
If upgrading Log4j is not immediately feasible, another method is to manually remove the vulnerable JndiLookup class from Log4j, which disables the ability to perform JNDI lookups.

You can do this by modifying the Log4j JAR file:
After finding the Log4j JAR file:

- Open the jar file: `jar -xf log4j-core-2.14.1.jar`

- Delete the JndiLookupClass by navigating to `org/apache/logging/log4j/core/lookup/` and deleting the `JndiLookup.class` file

- Re-package the JAR: `jar -cf log4j-core-2.14.1-fixed.jar -C path/to/unpacked/classes .` 

- Replace the old JAR file with the fixed one.

#### Through Configuration
If your application uses a Log4j configuration file (`log4j2.xml`), you can modify it to explicitly disable lookups by removing or not using lookup features (such as messagePattern that would process `${}`).

```xml
<Configuration>
    <Appenders>
        <Console name="Console" target="SYSTEM_OUT">
            <PatternLayout pattern="%d [%t] %-5level: %msg%n"/>
        </Console>
    </Appenders>
    <Loggers>
        <Root level="error">
            <AppenderRef ref="Console"/>
        </Root>
    </Loggers>
</Configuration>
```
In this example, no dynamic lookups (`${}`) are being used in the PatternLayout, thus preventing the vulnerable mechanism from being triggered.

#### Pros
This fixes the immediate issue and was the first hotfix made. It entirely disables the first concrete way of exploiting the vulnerability that was found. It's a temporary but effective workaround but effective while upgrading the log4j version is unfeasible for whatever reason.

#### Cons 
Not exhaustive
Disables some lookup features that may hamper the functionality of your web app

## A subtler approach
### Input Sanitization

You can implement input validation or sanitization to strip or escape dangerous characters (like `${}` used for JNDI lookups) before they are logged by Log4j.
For example, you could write a simple function to replace `${` with a harmless string:

```java
public String sanitizeInput(String input) {
    return input.replace("${", "\\${");
}
```

`logger.error("User input: " + sanitizeInput(userInput));`


### Firewall Rules and/or Network Controls
Another mitigation technique is to restrict outbound connections from your application server to block potentially malicious JNDI lookups.

#### Block Outbound LDAP/RMI Traffic
You can configure network firewalls or system-level firewalls (like iptables on Linux) to block outbound traffic to the following protocols:

- LDAP (Lightweight Directory Access Protocol), commonly used in Log4Shell exploits.
- RMI (Remote Method Invocation), another Java service that could be exploited via JNDI.

For example, on Linux, you could block outbound LDAP traffic by running:
```
iptables -A OUTPUT -p tcp --dport 389 -j DROP   # LDAP port
iptables -A OUTPUT -p tcp --dport 1389 -j DROP  # Commonly used for JNDI exploits
iptables -A OUTPUT -p tcp --dport 1099 -j DROP  # RMI port
```
This will prevent the vulnerable application from reaching remote servers that could serve malicious payloads. It won't stop the exploit itself from being attempted but will stop the server from fetching external code.

#### Using a Web Application Firewall
Deploying a Web Application Firewall (WAF) can help mitigate exploit attempts by filtering HTTP requests that contain suspicious payloads.

- Configure WAF Rules: Create custom rules to block requests containing `${jndi:ldap://, ${rmi://`, or similar strings often used in Log4Shell exploits.
- Many cloud providers and services (such as AWS WAF, Cloudflare, etc.) have released specific rules to block Log4Shell attempts.

