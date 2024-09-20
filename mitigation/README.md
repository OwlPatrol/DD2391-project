# Methods of Mitigation

## Identifying the Danger
*Describe what the exploit actually does and how it functions*

## The heavy-handed Approach
### Disabling JNDI lookups
#### What's JNDI?
The Java Naming and Directory Interface (JNDI) is a Java API that allows Java applications to look up data and objects in a variety of naming and directory services. Essentially, JNDI provides a standardized way for Java programs to access different kinds of naming and directory services, like DNS, LDAP (Lightweight Directory Access Protocol), and RMI (Remote Method Invocation) registries.

#### Through Configuration

#### Through Removing the JndiLookupClass from the Classpath

#### Pros
This fixes the immediate issue and was the first hotfix made. It entirely disables the first concrete way of exploiting the vulnerability that was found

#### Cons 
Not exhaustive
Disables some lookup features that may hamper the functionality of your web app

## A subtler approach
### Input Sanitization
