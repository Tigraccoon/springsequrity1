package io.security.basicsecurity;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
  @Autowired
  UserDetailsService userDetailsService;

  @Bean
  public SecurityFilterChain filterChain (HttpSecurity http) throws Exception {
    http
      .authorizeHttpRequests((authorizationManagerRequestMatcherRegistry -> authorizationManagerRequestMatcherRegistry
        .anyRequest()
        .authenticated()))
      .formLogin(httpSecurityFormLoginConfigurer -> httpSecurityFormLoginConfigurer
        //        .loginPage("/loginPage")
        .defaultSuccessUrl("/")
        .failureUrl("/login")
        .usernameParameter("userId")
        .passwordParameter("password")
        //        .loginProcessingUrl("/login_proc")
        //        .successHandler(new AuthenticationSuccessHandler() {
        //          @Override
        //          public void onAuthenticationSuccess (HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        //            System.out.println("authentication = " + authentication.getName());
        //          }
        //        })
        .failureHandler(new AuthenticationFailureHandler() {
          @Override
          public void onAuthenticationFailure (HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
            System.out.println("exception = " + exception.getMessage());
            response.sendRedirect("/");
          }
        })
        .permitAll()
      )
      .logout(httpSecurityLogoutConfigurer -> {
        httpSecurityLogoutConfigurer
          .logoutUrl("/logout")
          .logoutSuccessUrl("/login")
          .addLogoutHandler(new LogoutHandler() {
            @Override
            public void logout (HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
              HttpSession session = request.getSession();
              session.invalidate();
            }
          })
          .logoutSuccessHandler(new LogoutSuccessHandler() {
            @Override
            public void onLogoutSuccess (HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
              response.sendRedirect("/login");
            }
          })
          .deleteCookies("remember-me")
          .permitAll();
      })
      .rememberMe(httpSecurityRememberMeConfigurer -> {
        httpSecurityRememberMeConfigurer
          .rememberMeParameter("remember")
          .tokenValiditySeconds(3600)
          .userDetailsService(userDetailsService);
      })
    ;

    return http.build();
  }
}
