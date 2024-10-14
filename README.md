# DD2391-project

## Vulnerable App

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
