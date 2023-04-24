package com.example.security.config;

import com.example.security.filter.LoginFilter;
import com.example.security.handler.LogoutSuccessHandler;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.UrlAuthorizationConfigurer;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.*;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.security.SpringSessionBackedSessionRegistry;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Configuration
public class MySecurityConfig {

    private final UserDetailsServiceConfig userDetailsServiceConfig;

    private final DataSource dataSource;

    private final FindByIndexNameSessionRepository findByIndexNameSessionRepository;

    private final CustomerSecurityMetadataSource customSecurityMeatadataSource;

    private final AuthenticationConfiguration authenticationConfiguration;

    @Autowired
    public MySecurityConfig(
            UserDetailsServiceConfig userDetailsServiceConfig,
            DataSource dataSource,
            FindByIndexNameSessionRepository findByIndexNameSessionRepository,
            CustomerSecurityMetadataSource customSecurityMeatadataSource,
            AuthenticationConfiguration authenticationConfiguration
    ) {
        this.userDetailsServiceConfig = userDetailsServiceConfig;
        this.dataSource = dataSource;
        this.findByIndexNameSessionRepository = findByIndexNameSessionRepository;
        this.customSecurityMeatadataSource = customSecurityMeatadataSource;
        this.authenticationConfiguration = authenticationConfiguration;
    }

    // 配置密码加密算法 (全局)
    @Bean
    public PasswordEncoder passwordEncoder() {
        //这个表示使用明文密码
        // return NoOpPasswordEncoder.getInstance();
        //表示使用 bcrypt 做密码加密
        // return new BCryptPasswordEncoder();
        String encodingId = "bcrypt";
        Map<String, PasswordEncoder> encoders = new HashMap();
        encoders.put(encodingId, new BCryptPasswordEncoder(12));
        encoders.put("ldap", new LdapShaPasswordEncoder());
        encoders.put("MD4", new Md4PasswordEncoder());
        encoders.put("MD5", new MessageDigestPasswordEncoder("MD5"));
        encoders.put("noop", NoOpPasswordEncoder.getInstance());
        encoders.put("pbkdf2", new Pbkdf2PasswordEncoder());
        encoders.put("scrypt", new SCryptPasswordEncoder());
        encoders.put("SHA-1", new MessageDigestPasswordEncoder("SHA-1"));
        encoders.put("SHA-256", new MessageDigestPasswordEncoder("SHA-256"));
        encoders.put("sha256", new StandardPasswordEncoder());
        encoders.put("argon2", new Argon2PasswordEncoder());
        return new DelegatingPasswordEncoder(encodingId, encoders);
    }

    // 作用：依赖将自定义AuthenticationManager在工厂中进行暴露，可以在任何位置注入
    @Bean
    AuthenticationManager authenticationManagerBean() throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    // 自定义 RememberMeServices 设置为Bean
    @Bean
    public RememberMeServices rememberMeServices() {
        return new PersistentTokenBasedRememberMeServicesConfig(UUID.randomUUID().toString(), userDetailsServiceConfig, persistentTokenRepository());
    }

    // 自定义持久化令牌仓库 (记住我)
    @Bean
    public PersistentTokenRepository persistentTokenRepository() {
        JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();
        jdbcTokenRepository.setDataSource(dataSource);
        jdbcTokenRepository.setCreateTableOnStartup(false); // 启动时创建表结构
        return jdbcTokenRepository;
    }

    // UsernamePasswordAuthenticationFilter 改写，认证拦截器
    @Bean
    public LoginFilter loginFilter() throws Exception {
        LoginFilter loginFilter = new LoginFilter();
        loginFilter.setFilterProcessesUrl("/doLogin"); // 指定认证的 url
        loginFilter.setUsernameParameter("uname"); // 用于指定 json 用户名 key
        loginFilter.setPasswordParameter("passwd"); // 用于指定 json 密码 key
        loginFilter.setKaptchaParameter("kaptcha"); // 用于指定 json 验证码 key
        loginFilter.setAuthenticationManager(authenticationManagerBean()); // 用于指定 authenticationManager
        loginFilter.setAuthenticationSuccessHandler(((request, response, authentication) -> {
            Map<String, Object> result = new HashMap<>();
            result.put("msg", "登录成功");
            result.put("用户信息", authentication.getPrincipal());
            response.setContentType("application/json;charset=UTF-8");
            response.setStatus(HttpStatus.OK.value());
            String s = new ObjectMapper().writeValueAsString(result);
            response.getWriter().println(s);
        })); // 认证成功处理
        loginFilter.setAuthenticationFailureHandler(((request, response, exception) -> {
            Map<String, Object> result = new HashMap<>();
            result.put("msg", "登录失败: " + exception.getMessage());
            response.setContentType("application/json;charset=UTF-8");
            response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
            String s = new ObjectMapper().writeValueAsString(result);
            response.getWriter().println(s);
        })); // 认证失败处理
        loginFilter.setRememberMeServices(rememberMeServices()); // 用于指定认证成功时使用自定义 rememberMeServices
        return loginFilter;
    }

    // 创建 session 同步到 redis 方案
    @Bean
    public SpringSessionBackedSessionRegistry sessionRegistry() {
        return new SpringSessionBackedSessionRegistry(findByIndexNameSessionRepository);
    }

    // 跨域处理方案配置 springSecurity 实现 (推荐，不会出现类似拦截器失效问题)
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowedHeaders(Arrays.asList("*"));
        corsConfiguration.setAllowedMethods(Arrays.asList("*"));
        corsConfiguration.setAllowedOrigins(Arrays.asList("*"));
        corsConfiguration.setMaxAge(3600L);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfiguration);
        return source;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.authorizeHttpRequests()
                .mvcMatchers("/login.html").permitAll() // 放行资源
                .mvcMatchers("/vc.jpg").permitAll()
                .anyRequest().authenticated() // 需要认证的资源
                .and()
                .formLogin()
                .and()
                .userDetailsService(userDetailsServiceConfig)
                .exceptionHandling()
                .authenticationEntryPoint(((request, response, authException) -> {
                    response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
                    response.setStatus(HttpStatus.UNAUTHORIZED.value());
                    response.getWriter().println("请认证以后再去处理!");
                }))
                .accessDeniedHandler(((request, response, accessDeniedException) -> {
                    response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
                    response.setStatus(HttpStatus.FORBIDDEN.value());
                    response.getWriter().println("无权访问");
                }))
                .and()
                .logout() // 开启注销功能
                .logoutRequestMatcher(new OrRequestMatcher( // 指定注销登录 url
                        new AntPathRequestMatcher("/logout", HttpMethod.DELETE.name()),
                        new AntPathRequestMatcher("/logout", HttpMethod.GET.name())
                ))
                .invalidateHttpSession(true) // 默认 会话失效
                .clearAuthentication(true) // 清除认证标记
                .logoutSuccessHandler(new LogoutSuccessHandler()) // 注销成功处理方案
                .and()
                .rememberMe() //开启记住我功能
                .rememberMeServices(rememberMeServices()) // 设置自动登录1使用哪个 rememberMeServices
                .tokenRepository(persistentTokenRepository()) // 指定自定义token存储方式
                .tokenValiditySeconds(60 * 60 * 24 * 14) // token实现时间，默认是14天
                .and()
                .csrf() // 开启 csrf 保护(非幂等) (传统web开发只需开启，前端模板的表单会自动生成_csrf的隐藏输入框)
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()) // 将令牌保存到 cookie 中，允许 cookie 前端获取，前后端分离
                .ignoringAntMatchers("/doLogin") // csrf 忽视路径，可不用令牌，登录认证路径建议忽视
                .and()
                .cors() // 跨域处理方案
                .configurationSource(corsConfigurationSource())
                .and()
                .sessionManagement() // 开启会话管理
                .maximumSessions(1) // 设置最大会话数 (后者会挤掉前者)
                .expiredSessionStrategy(event -> {
                    HttpServletResponse response = event.getResponse();
                    Map<String, Object> result = new HashMap<>();
                    result.put("status", 500);
                    result.put("msg", "当前会话已经实现, 请重新登录!");
                    String s = new ObjectMapper().writeValueAsString(result);
                    response.setContentType("application/json;charset=UTF-8");
                    response.getWriter().println(s);
                    response.flushBuffer();
                })
                .sessionRegistry(sessionRegistry()) // 将 session 交给谁管理 (实现集群 session 并发)
                .maxSessionsPreventsLogin(true); // 后者无法登录 (不会被挤下线)

        // 获取工厂对象
        ApplicationContext applicationContext = httpSecurity.getSharedObject(ApplicationContext.class);
        // 设置自定义 url 权限处理
        httpSecurity.apply(new UrlAuthorizationConfigurer<>(applicationContext))
                .withObjectPostProcessor(new ObjectPostProcessor<FilterSecurityInterceptor>() {
                    @Override
                    public <O extends FilterSecurityInterceptor> O postProcess(O object) {
                        object.setSecurityMetadataSource(customSecurityMeatadataSource);
                        // 是否拒绝公告资源的访问 (没被权限限制的资源)
                        object.setRejectPublicInvocations(false);
                        return object;
                    }
                });

        // 替换默认的认证方案VerifyCodeControllerVerifyCodeController
        httpSecurity.addFilterAt(loginFilter(), UsernamePasswordAuthenticationFilter.class);

        return httpSecurity.build();
    }
}
