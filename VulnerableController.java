
package com.example.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/vulnerable")
public class VulnerableController {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    private static final String API_KEY = "supersecretapikey123"; // Hardcoded secret

    // 1. SQL Injection
    @GetMapping("/users")
    public List<Map<String, Object>> getUsers(@RequestParam String username) {
        // Vulnerable to SQL Injection
        String sql = "SELECT * FROM users WHERE username = '" + username + "'";
        return jdbcTemplate.queryForList(sql);
    }

    // 2. Command Injection
    @GetMapping("/exec")
    public String executeCommand(@RequestParam String command) throws IOException {
        // Vulnerable to Command Injection
        Process process = Runtime.getRuntime().exec(command);
        InputStream inputStream = process.getInputStream();
        return new String(inputStream.readAllBytes());
    }

    // 3. Path Traversal
    @GetMapping("/file")
    public String getFileContent(@RequestParam String filename) throws IOException {
        // Vulnerable to Path Traversal
        File file = new File("/var/www/html/" + filename);
        return new String(Files.readAllBytes(file.toPath()));
    }

    // 4. Insecure Deserialization
    @PostMapping("/deserialize")
    public String deserializeData(HttpServletRequest request) throws IOException, ClassNotFoundException {
        // Vulnerable to Insecure Deserialization
        InputStream data = request.getInputStream();
        ObjectInputStream ois = new ObjectInputStream(data);
        Object obj = ois.readObject();
        ois.close();
        return "Deserialized object: " + obj.toString();
    }

    // 5. Cross-Site Scripting (XSS) - Reflected
    @GetMapping("/greeting")
    public String greeting(@RequestParam(name="name", required=false, defaultValue="World") String name) {
        // Vulnerable to Reflected XSS
        return "<h1>Hello, " + name + "!</h1>";
    }

}
