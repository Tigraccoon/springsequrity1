package io.security.basicsecurity;

import jakarta.servlet.http.HttpSession;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
  //  @Autowired
  //  UserDetailsService userDetailsService;

  @Bean
  public UserDetailsManager setInMemoryUsers () {
    UserDetails user = User
      .builder()
      .username("user")
      .password("{noop}1234")
      .roles("USER")
      .build();

    UserDetails sys = User
      .builder()
      .username("sys")
      .password("{noop}1234")
      .roles("SYS", "USER")
      .build();

    UserDetails admin = User
      .builder()
      .username("admin")
      .password("{noop}1234")
      .roles("ADMIN", "SYS", "USER")
      .build();

    return new InMemoryUserDetailsManager(user, sys, admin);
  }

  @Bean
  public SecurityFilterChain filterChain (HttpSecurity http) throws Exception {
    http
      .authorizeHttpRequests((authorizationManagerRequestMatcherRegistry -> authorizationManagerRequestMatcherRegistry
        //        .requestMatchers("/denied")
        //        .permitAll()
        .requestMatchers("/user")
        .hasRole("USER")
        .requestMatchers("/admin/pay")
        .hasRole("ADMIN")
        .requestMatchers("/admin/**")
        .hasAnyRole("ADMIN", "SYS")
        .anyRequest()
        .authenticated()))
      .formLogin(httpSecurityFormLoginConfigurer -> httpSecurityFormLoginConfigurer
        //        .loginPage("/loginPage")
        .defaultSuccessUrl("/")
        .failureUrl("/login")
        .usernameParameter("userId")
        .passwordParameter("password")
        //        .loginProcessingUrl("/login_proc")
        .successHandler((request, response, authentication) -> {
          RequestCache requestCache = new HttpSessionRequestCache();
          SavedRequest savedRequest = requestCache.getRequest(request, response);
          response.sendRedirect(savedRequest
            .getRedirectUrl()
            .isEmpty() ? "/home" : savedRequest.getRedirectUrl());
        })
        .failureHandler((request, response, exception) -> {
          System.out.println("exception = " + exception.getMessage());
          response.sendRedirect("/");
        })
        .permitAll()
      )
      .logout(httpSecurityLogoutConfigurer -> httpSecurityLogoutConfigurer
        .logoutUrl("/logout")
        .logoutSuccessUrl("/login")
        .addLogoutHandler((request, response, authentication) -> {
          HttpSession session = request.getSession();
          session.invalidate();
        })
        .logoutSuccessHandler((request, response, authentication) -> response.sendRedirect("/login"))
        .deleteCookies("remember-me")
        .permitAll())
      //      .rememberMe(httpSecurityRememberMeConfigurer -> httpSecurityRememberMeConfigurer
      //        .rememberMeParameter("remember")
      //        .tokenValiditySeconds(3600)
      //        .userDetailsService(userDetailsService))
      .sessionManagement(httpSecuritySessionManagementConfigurer -> httpSecuritySessionManagementConfigurer
        .maximumSessions(1)
        .maxSessionsPreventsLogin(false)
        .expiredUrl("/login"))
      .exceptionHandling(httpSecurityExceptionHandlingConfigurer -> httpSecurityExceptionHandlingConfigurer
        //        .authenticationEntryPoint((request, response, authException) -> {
        //          response.sendRedirect("/login");
        //        })
        .accessDeniedHandler((request, response, accessDeniedException) -> {
          response.sendRedirect("/denied");
        }))
    ;

    return http.build();
  }
}
