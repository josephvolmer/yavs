package com.example;

import java.io.*;
import java.sql.*;
import java.util.Random;
import javax.servlet.http.*;

/**
 * Intentionally vulnerable Java application for testing SAST scanners
 */
public class VulnerableApp {

    // Hardcoded credentials
    private static final String DB_PASSWORD = "admin123";
    private static final String API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz";

    // SQL Injection vulnerability
    public User getUser(String username) throws SQLException {
        Connection conn = DriverManager.getConnection(
            "jdbc:mysql://localhost:3306/mydb",
            "root",
            DB_PASSWORD
        );

        // Unsafe: SQL injection
        String query = "SELECT * FROM users WHERE username = '" + username + "'";
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(query);

        User user = null;
        if (rs.next()) {
            user = new User(rs.getString("username"), rs.getString("email"));
        }

        rs.close();
        stmt.close();
        conn.close();

        return user;
    }

    // Command Injection vulnerability
    public String executeCommand(String cmd) throws IOException {
        // Unsafe: command injection
        Runtime runtime = Runtime.getRuntime();
        Process process = runtime.exec(cmd);

        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );

        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }

        return output.toString();
    }

    // Path Traversal vulnerability
    public String readFile(String filename) throws IOException {
        // Unsafe: path traversal
        FileInputStream fis = new FileInputStream(filename);
        BufferedReader reader = new BufferedReader(new InputStreamReader(fis));

        StringBuilder content = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            content.append(line).append("\n");
        }

        reader.close();
        return content.toString();
    }

    // XSS vulnerability
    public void handleRequest(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String userInput = request.getParameter("input");

        // Unsafe: reflected XSS
        response.getWriter().write("<h1>You entered: " + userInput + "</h1>");
    }

    // Insecure random for security purposes
    public String generateToken() {
        Random random = new Random();
        // Unsafe: Random is not cryptographically secure
        return String.valueOf(random.nextInt(999999));
    }

    // Deserialization vulnerability
    public Object deserializeObject(byte[] data) throws IOException, ClassNotFoundException {
        ByteArrayInputStream bis = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bis);

        // Unsafe: untrusted deserialization
        return ois.readObject();
    }

    // Weak cryptography
    public String weakHash(String password) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
            byte[] array = md.digest(password.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : array) {
                sb.append(Integer.toHexString((b & 0xFF) | 0x100).substring(1, 3));
            }
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }

    // Helper class
    static class User {
        private String username;
        private String email;

        public User(String username, String email) {
            this.username = username;
            this.email = email;
        }

        public String getUsername() { return username; }
        public String getEmail() { return email; }
    }
}
