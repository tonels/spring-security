package com.example.springsecurity.config;

import com.example.springsecurity.security.LoginFailureHandler;
import com.example.springsecurity.security.LoginSuccessHandler;
import com.example.springsecurity.security.LogoutSuccessHandlerImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    /**
     * 配置初始化用户
     * @param auth
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//         设置配置 在 auth 对象上
        auth.inMemoryAuthentication()
                .withUser("user").password("user").roles("USER")
             .and()
                .withUser("admin").password("admin").roles("ADMIN")
             .and()
                .withUser("ls").password("ls").roles("DEV");
    }

    /**
     * 此处定义密码加密规则
     * BCryptPasswordEncoder 默认的是SHA-256 +随机盐+密钥对密码进行加密，采用hash算法，不可逆
     * NoOpPasswordEncoder.getInstance() 可设置对密码不加密
     * todo jasypt可替换加密规则，并提供 加/解 密
     * @return
     */
    @Bean
    public PasswordEncoder getPasswordEncoder() {
        return NoOpPasswordEncoder.getInstance(); //
    }
    /**
     * 此处配置接口权限
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .csrf()
            .disable()
                // 给角色授接口权限
            .authorizeRequests()
                .antMatchers("/admin").hasRole("ADMIN")
                .antMatchers("/user").hasAnyRole("USER", "ADMIN")
                .antMatchers("/").permitAll()
            .and()
                // 登录拦截处理
                .formLogin()
                    .successHandler(loginSuccessHandler())
                    .failureHandler(authenticationFailureHandler())
            .and()
                // 退出拦截处理
                .logout()
                    .logoutUrl("/logout")
                    .permitAll();
//                    .logoutSuccessHandler(logoutSuccessHandler());
    }

    @Bean
    public LoginSuccessHandler loginSuccessHandler(){
        return new LoginSuccessHandler();
    }
    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler(){
        return new LoginFailureHandler();
    }
    @Bean
    public LogoutSuccessHandler logoutSuccessHandler(){
        return new LogoutSuccessHandlerImpl();
    }



}
