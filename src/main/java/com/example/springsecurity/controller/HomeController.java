package com.example.springsecurity.controller;

import com.example.springsecurity.security.SecurityUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
@RequestMapping
public class HomeController {


    @GetMapping("/")
    public String index() {
        return "<h1>" +SecurityUtils.getCurrentUserLogin();
    }

    @GetMapping("/user")
    public String user() {
        return "<h1> 普通用户的权限";
    }

    @GetMapping("/admin")
    public String admin() {
        return "<h1> 管理员的的权限";
    }

    /**
     * 获取当前用户信息（userName）
     * 无用户登陆时 返回 anonymousUser
     *
     * @param request
     * @return
     */
    @GetMapping("/currentUser")
    public String currentUser(HttpServletRequest request) {
        return SecurityUtils.getCurrentUserLogin();
    }

    /**
     * todo
     * 在 securityConfig中配置 logout
     * 是不需要单独定义接口的？？
     */
//    @GetMapping("/logout")
//    public void logout(){
//
//    }


}
