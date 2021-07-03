# Spring Security Demo

## Spring Security 基本原理
> Spring Security 本质上是一个过滤器链 有很多过滤器

## 常用过滤器
```java
//方法级过滤器，位于过滤器链的最底端
org.springframework.security.web.access.intercept.FilterSecurityInterceptor
//异常过滤器，用来处理在认证授权过程中抛出的异常
org.springframework.security.web.access.ExceptionTranslationFilter
//对/login的POST请求做拦截，校验表单中的用户名和密码
org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
```

## 过滤器加载过程

```java
// 手动配置时
//1.在web.xml中添加过滤器
org.springframework.web.filter.DelegatingFilterProxy
//2.初始化FilterChainProxy
if (delegateToUse == null) {
    synchronized (this.delegateMonitor) {
        delegateToUse = this.delegate;
        if (delegateToUse == null) {
            WebApplicationContext wac = findWebApplicationContext();
            if (wac == null) {
                throw new IllegalStateException("No WebApplicationContext found: " +
                                                "no ContextLoaderListener or DispatcherServlet registered?");
            }
            delegateToUse = initDelegate(wac);
        }
        this.delegate = delegateToUse;
    }
}
//3.得到过滤器链
private void doFilterInternal(ServletRequest request, ServletResponse response,
			FilterChain chain) throws IOException, ServletException {

    FirewalledRequest fwRequest = firewall
        .getFirewalledRequest((HttpServletRequest) request);
    HttpServletResponse fwResponse = firewall
        .getFirewalledResponse((HttpServletResponse) response);

    List<Filter> filters = getFilters(fwRequest);

    if (filters == null || filters.size() == 0) {
        if (logger.isDebugEnabled()) {
            logger.debug(UrlUtils.buildRequestUrl(fwRequest)
                         + (filters == null ? " has no matching filters"
                            : " has an empty filter list"));
        }

        fwRequest.reset();

        chain.doFilter(fwRequest, fwResponse);

        return;
    }

    VirtualFilterChain vfc = new VirtualFilterChain(fwRequest, chain, filters);
    vfc.doFilter(fwRequest, fwResponse);
}
```

## UserDetailService详解

```java
// 该接口主要是用来查询数据库用户名和密码的过程
public interface UserDetailsService {
	/**
	 * Locates the user based on the username. In the actual implementation, the search
	 * may possibly be case sensitive, or case insensitive depending on how the
	 * implementation instance is configured. In this case, the <code>UserDetails</code>
	 * object that comes back may have a username that is of a different case than what
	 * was actually requested..
	 *
	 * @param username the username identifying the user whose data is required.
	 *
	 * @return a fully populated user record (never <code>null</code>)
	 *
	 * @throws UsernameNotFoundException if the user could not be found or the user has no
	 * GrantedAuthority
	 */
	UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
}
```

## PasswordEncoder详解

```java
// 该接口对返回的User的密码进行加密
public interface PasswordEncoder {

	/**
	 * Encode the raw password. Generally, a good encoding algorithm applies a SHA-1 or
	 * greater hash combined with an 8-byte or greater randomly generated salt.
	 */
	String encode(CharSequence rawPassword);

	/**
	 * Verify the encoded password obtained from storage matches the submitted raw
	 * password after it too is encoded. Returns true if the passwords match, false if
	 * they do not. The stored password itself is never decoded.
	 *
	 * @param rawPassword the raw password to encode and match
	 * @param encodedPassword the encoded password from storage to compare with
	 * @return true if the raw password, after encoding, matches the encoded password from
	 * storage
	 */
	boolean matches(CharSequence rawPassword, String encodedPassword);

	/**
	 * Returns true if the encoded password should be encoded again for better security,
	 * else false. The default implementation always returns false.
	 * @param encodedPassword the encoded password to check
	 * @return true if the encoded password should be encoded again for better security,
	 * else false.
	 */
	default boolean upgradeEncoding(String encodedPassword) {
		return false;
	}
}
```

## 一般的编写认证过程

```java
创建类继承UsernamePasswordAuthenticationFilter重写三个方法
// 1.UsernamePasswordAuthenticationFilter类的attemptAuthentication方法
// 2.AbstractAuthenticationProcessingFilter类的successfulAuthentication和unsuccessfulAuthentication方法
创建类实现UserDetailService接口，编写查询用户数据过程，返回security提供的User对象
```

## WEB权限方案

> 设置登录的用户名和密码
>
> 1. 通过配置文件
>
> ```properties
> spring.security.user.name=admin
> spring.security.user.password=123456
> ```
>
> 2. 通过配置类
>
> ```java
> @Configuration
> public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {
>     @Override
>     protected void configure(AuthenticationManagerBuilder auth) throws Exception {
>         BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
>         String encode = passwordEncoder.encode("123456");
>         System.out.println(encode);
>         auth.inMemoryAuthentication().withUser("admin").password(encode).roles("admin");
>     }
> 
>     @Bean
>     public PasswordEncoder passwordEncoder(){
>         return new BCryptPasswordEncoder();
>     }
> }
> ```

> 3.自定义实现类设置
>
> 1. 创建配置类，设置使用哪个UserDetailsService实现类
> 2. 编写实现类，返回User对象，User对象有用户名密码和操作权限
>
> ```java
> @Service
> public class MyUserDetailsService implements UserDetailsService {
>     @Override
>     public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
>         List<GrantedAuthority> role = AuthorityUtils.createAuthorityList("role");
>         return new User("admin",new BCryptPasswordEncoder().encode("666666"),role);
>     }
> }
> 
> @Configuration
> @EnableWebSecurity
> public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {
> 
>     @Autowired
>     private UserDetailsService userDetailsService;
> 
>     @Override
>     protected void configure(AuthenticationManagerBuilder auth) throws Exception {
>         auth.userDetailsService(userDetailsService);
>     }
> 
>     @Bean
>     public PasswordEncoder passwordEncoder(){
>         return new BCryptPasswordEncoder();
>     }
> }
> ```

## 自定义设置登录页面

```java
@Configuration
@EnableWebSecurity
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin() //自定义自己编写的页面
                .loginPage("/login.html") //登录页面设置
                .loginProcessingUrl("/login/in") //登录访问路径
                .defaultSuccessUrl("/index") //登录成功之后跳转路径
                .and().authorizeRequests().antMatchers("/","/login.html","/login/in").permitAll()
                .anyRequest().authenticated()
                .and().csrf().disable();
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
```

