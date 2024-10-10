import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.net.InetSocketAddress;

public class App implements HttpHandler {
    private App() {}

    private static final Logger logger = LogManager.getLogger(App.class);

    public static void main(String[] args) throws IOException {

        var listenAny = args.length > 0 && args[0].equals("listen-any");

        HttpServer server = HttpServer.create(
            listenAny ?
                new InetSocketAddress(8080) :
                new InetSocketAddress("127.0.0.1", 8080),
            0
        );

        server.createContext("/", new App());

        server.setExecutor(null);
        server.start();

        logger.info("Started server on http://" + (listenAny ? "0.0.0.0" : "127.0.0.1") + ":8080");
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        var method = exchange.getRequestMethod();
        var path = exchange.getRequestURI().getPath();
        var clientIp = exchange.getRemoteAddress().getAddress().getHostAddress();
        var userAgent = exchange.getRequestHeaders().getFirst("User-Agent");
        var accept = exchange.getRequestHeaders().getFirst("Accept");

        String sanitizedUserAgent = sanitizeInput(userAgent);

        logger.info("{} {} {} {} {}", method, path, clientIp, userAgent, accept);

        var response = "Hello, this a the HTTP server!";
        exchange.sendResponseHeaders(200, response.getBytes().length);
        var os = exchange.getResponseBody();
        os.write(response.getBytes());
        os.close();
    }


        // Static method to sanitize input
        public static String sanitizeInput(String input) {
            if (input == null) {
                return null;
            }
            // Remove all occurrences of '${...}'
            return input.replaceAll("\\$\\{.*?\\}", "");
        }


}
