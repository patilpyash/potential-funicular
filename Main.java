import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class Main {

    private static final Map<String, User> users = new HashMap<>();

    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(3000), 0);

        // Register routes
        server.createContext("/register", new RegisterHandler());
        server.createContext("/forgot-password", new ForgotPasswordHandler());
        server.createContext("/reset-password", new ResetPasswordHandler());
        server.createContext("/login", new LoginHandler());
        server.createContext("/user", new UserHandler());

        server.start();
        System.out.println("Server started on port 3000");
    }

    static class RegisterHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("POST".equals(exchange.getRequestMethod())) {
                InputStream requestBody = exchange.getRequestBody();
                BufferedReader reader = new BufferedReader(new InputStreamReader(requestBody, StandardCharsets.UTF_8));
                String requestBodyString = reader.readLine();

                // Parse JSON request body
                // (In a production environment, you might want to use a JSON library for better
                // parsing)
                String[] parts = requestBodyString.split("&");
                String name = parts[0].split("=")[1];
                String email = parts[1].split("=")[1];
                String password = parts[2].split("=")[1];

                // Validate
                if (name.isEmpty() || email.isEmpty() || password.isEmpty()) {
                    sendResponse(exchange, 400, "Please enter all fields");
                    return;
                }

                // Hash the password before storing it
                String hashedPassword = hashPassword(password);
                User newUser = new User(name, email, hashedPassword);
                users.put(email, newUser);

                sendResponse(exchange, 200, "User registered!");
            }
        }
    }

    static class ForgotPasswordHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("POST".equals(exchange.getRequestMethod())) {
                InputStream requestBody = exchange.getRequestBody();
                BufferedReader reader = new BufferedReader(new InputStreamReader(requestBody, StandardCharsets.UTF_8));
                String requestBodyString = reader.readLine();

                // Parse JSON request body
                // (In a production environment, you might want to use a JSON library for better
                // parsing)
                String email = requestBodyString.split("=")[1];

                if (email.isEmpty()) {
                    sendResponse(exchange, 400, "Please enter your email address");
                    return;
                }

                // Check if the user exists
                User user = users.get(email);
                if (user == null) {
                    sendResponse(exchange, 404, "User not found!");
                    return;
                }

                // Generate a unique reset token
                String resetToken = generateResetToken();

                // Store the reset token and its expiration time
                user.setResetToken(resetToken);

                sendResetTokenEmail(email, resetToken);

                sendResponse(exchange, 200, "Password reset token sent to your email");
            }
        }
    }

    static class ResetPasswordHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("POST".equals(exchange.getRequestMethod())) {
                InputStream requestBody = exchange.getRequestBody();
                BufferedReader reader = new BufferedReader(new InputStreamReader(requestBody, StandardCharsets.UTF_8));
                String requestBodyString = reader.readLine();

                // Parse JSON request body
                // (In a production environment, you might want to use a JSON library for better
                // parsing)
                String[] parts = requestBodyString.split("&");
                String email = parts[0].split("=")[1];
                String resetToken = parts[1].split("=")[1];
                String newPassword = parts[2].split("=")[1];

                if (email.isEmpty() || resetToken.isEmpty() || newPassword.isEmpty()) {
                    sendResponse(exchange, 400, "Please enter your email, reset token, and new password");
                    return;
                }

                // Check if the user exists
                User user = users.get(email);
                if (user == null) {
                    sendResponse(exchange, 404, "User not found!");
                    return;
                }

                // Check if the reset token is valid
                if (!user.getResetToken().equals(resetToken)) {
                    sendResponse(exchange, 401, "Invalid or expired reset token");
                    return;
                }

                // Hash the new password
                String hashedPassword = hashPassword(newPassword);

                // Update the user's password and clear the reset token
                user.setPassword(hashedPassword);
                user.setResetToken(null);

                sendResponse(exchange, 200, "Password reset successfully");
            }
        }
    }

    static class LoginHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("POST".equals(exchange.getRequestMethod())) {
                InputStream requestBody = exchange.getRequestBody();
                BufferedReader reader = new BufferedReader(new InputStreamReader(requestBody, StandardCharsets.UTF_8));
                String requestBodyString = reader.readLine();

                // Parse JSON request body
                // (In a production environment, you might want to use a JSON library for better
                // parsing)
                String[] parts = requestBodyString.split("&");
                String email = parts[0].split("=")[1];
                String password = parts[1].split("=")[1];

                if (email.isEmpty() || password.isEmpty()) {
                    sendResponse(exchange,
                            400, "Please enter email and password");
                    return;
                }

                // Check if the user exists
                User user = users.get(email);
                if (user == null) {
                    sendResponse(exchange, 401, "User not found!");
                    return;
                }

                // Compare hashed passwords
                if (!checkPassword(password, user.getPassword())) {
                    sendResponse(exchange, 401, "Invalid credentials!");
                    return;
                }

                // Set token expiration to 1 minute if not staying logged in, otherwise, set it
                // to a longer duration
                String expiresIn = "1m";

                // Create a simple token (You may want to implement a more secure token system)
                String token = createToken(user.getId(), user.getName(), user.getEmail(), expiresIn);

                sendResponse(exchange, 200, "{\"token\": \"" + token + "\", \"user\": {\"id\": " + user.getId()
                        + ", \"name\": \"" + user.getName() + "\", \"email\": \"" + user.getEmail() + "\"}}");
            }
        }
    }

    static class UserHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("GET".equals(exchange.getRequestMethod())) {
                // Extract the token from the Authorization header
                String token = exchange.getRequestHeaders().getFirst("Authorization");
                if (token == null || token.isEmpty()) {
                    sendResponse(exchange, 401, "No token found!");
                    return;
                }

                // Verify the token (This is a simple check, for real-world scenarios, you'd
                // need a more secure approach)
                String[] tokenParts = token.split(" ");
                if (tokenParts.length != 2) {
                    sendResponse(exchange, 403, "Invalid or expired token!");
                    return;
                }

                // Check if the token has expired
                String[] claims = tokenParts[1].split("\\.");
                if (claims.length != 3) {
                    sendResponse(exchange, 403, "Token has expired!");
                    return;
                }

                // Extract user information from the token
                String[] userClaims = new String(Base64.getDecoder().decode(claims[1]), StandardCharsets.UTF_8)
                        .split(",");
                int userId = Integer.parseInt(userClaims[0].split(":")[1]);
                String userName = userClaims[1].split(":")[1];
                String userEmail = userClaims[2].split(":")[1];

                sendResponse(exchange, 200, "{\"user\": {\"id\": " + userId + ", \"name\": \"" + userName
                        + "\", \"email\": \"" + userEmail + "\"}}");
            }
        }
    }

    private static void sendResponse(HttpExchange exchange, int statusCode, String response) throws IOException {
        exchange.sendResponseHeaders(statusCode, response.getBytes().length);
        OutputStream os = exchange.getResponseBody();
        os.write(response.getBytes());
        os.close();
    }

    private static String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashedPassword = md.digest(password.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hashedPassword);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static boolean checkPassword(String inputPassword, String hashedPassword) {
        return hashPassword(inputPassword).equals(hashedPassword);
    }

    private static String generateResetToken() {
        return UUID.randomUUID().toString();
    }

    private static void sendResetTokenEmail(String email, String resetToken) {
        // Implement your email sending logic here
        // You might want to use a library like JavaMail for email sending
        System.out.println("Reset token sent to email: " + email);
    }

    private static String createToken(int id, String name, String email, String expiresIn) {
        // This is a simple token creation for demonstration purposes
        // In a real-world scenario, you should use a secure JWT library
        return Base64.getEncoder().encodeToString(("{" +
                "\"id\":" + id + "," +
                "\"name\":\"" + name + "\"," +
                "\"email\":\"" + email + "\"," +
                "\"exp\":" + (System.currentTimeMillis() + Long.parseLong(expiresIn) * 1000) +
                "}").getBytes());
    }

    static class User {
        private static int nextId = 1;

        private final int id;
        private final String name;
        private final String email;
        private String password;
        private String resetToken;

        public User(String name, String email, String password) {
            this.id = nextId++;
            this.name = name;
            this.email = email;
            this.password = password;
        }

        public int getId() {
            return id;
        }

        public String getName() {
            return name;
        }

        public String getEmail() {
            return email;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }

        public String getResetToken() {
            return resetToken;
        }

        public void setResetToken(String resetToken) {
            this.resetToken = resetToken;
        }
    }
}
