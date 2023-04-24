package com.example.security.config;

import org.springframework.core.log.LogMessage;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.rememberme.AbstractRememberMeServices;
import org.springframework.security.web.authentication.rememberme.PersistentTokenBasedRememberMeServices;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.util.ObjectUtils;

import javax.servlet.http.HttpServletRequest;

/**
 * 自定义记住我 services 实现类
 */
public class PersistentTokenBasedRememberMeServicesConfig extends PersistentTokenBasedRememberMeServices {

    public PersistentTokenBasedRememberMeServicesConfig(String key, UserDetailsService userDetailsService, PersistentTokenRepository tokenRepository) {
        super(key, userDetailsService, tokenRepository);
    }

    /**
     * 自定义前后端分离获取 remember-me方式
     *
     * @param request
     * @param parameter
     * @return
     */
    @Override
    protected boolean rememberMeRequested(HttpServletRequest request, String parameter) {
        String paramValue = request.getAttribute(AbstractRememberMeServices.DEFAULT_PARAMETER).toString();
        if (!ObjectUtils.isEmpty(paramValue)) {
            if (paramValue.equalsIgnoreCase("true") || paramValue.equalsIgnoreCase("on")
                    || paramValue.equalsIgnoreCase("yes") || paramValue.equalsIgnoreCase("1")) {
                return true;
            }
        }
        this.logger.debug(LogMessage.format("Did not send remember-me cookie (principal did not set parameter '%s')", parameter));
        return false;
    }
}
