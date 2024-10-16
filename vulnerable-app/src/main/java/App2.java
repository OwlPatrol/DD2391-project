import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;

public class App2 implements HttpHandler {
    private App2() {}

    private static final Logger logger = LogManager.getLogger(App2.class);

    public static void main(String[] args) throws IOException {
        boolean listenAny = args.length > 0 && args[0].equals("listen-any");

        HttpServer server = HttpServer.create(
            listenAny ?
                new InetSocketAddress(8080) :
                new InetSocketAddress("127.0.0.1", 8080),
            0
        );

        server.createContext("/", new App2());

        server.setExecutor(null);
        server.start();

        logger.info("Started server 2 on http://" + (listenAny ? "0.0.0.0" : "127.0.0.1") + ":8080");
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        String method = exchange.getRequestMethod();
        String path = exchange.getRequestURI().getPath();
        String clientIp = exchange.getRemoteAddress().getAddress().getHostAddress();
        String userAgent = exchange.getRequestHeaders().getFirst("User-Agent");
        String accept = exchange.getRequestHeaders().getFirst("Accept");
        logger.info("{} {} {} {} {}", method, path, clientIp, userAgent, accept);

        String response = "Hello, this a the HTTP server!";
        exchange.sendResponseHeaders(200, response.getBytes().length);
        OutputStream os = exchange.getResponseBody();
        os.write(response.getBytes());
        os.close();
    }
}
