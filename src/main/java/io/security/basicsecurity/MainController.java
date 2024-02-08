package io.security.basicsecurity;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MainController {

  @GetMapping("/")
  public String home () {
    return "hi";
  }

  @GetMapping("/loginPage")
  public String loginPage () {
    return "loginPage";
  }

  @GetMapping("/admin")
  public String admin () {
    return "admin";
  }

  @GetMapping("/admin/**")
  public String adminAny () {
    return "admin **";
  }

  @GetMapping("/user")
  public String user () {
    return "user";
  }
}
