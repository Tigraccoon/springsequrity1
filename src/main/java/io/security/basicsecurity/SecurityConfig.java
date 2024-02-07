package io.security.basicsecurity;

import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
  @Autowired
  UserDetailsService userDetailsService;

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
      .roles("SYS")
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
      .rememberMe(httpSecurityRememberMeConfigurer -> httpSecurityRememberMeConfigurer
        .rememberMeParameter("remember")
        .tokenValiditySeconds(3600)
        .userDetailsService(userDetailsService))
      .sessionManagement(httpSecuritySessionManagementConfigurer -> httpSecuritySessionManagementConfigurer
        .maximumSessions(1)
        .maxSessionsPreventsLogin(false)
        .expiredUrl("/login"))
    ;

    return http.build();
  }
}
