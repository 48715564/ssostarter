package daocloud.oauth2.sso.filter;

import cn.hutool.cache.CacheUtil;
import cn.hutool.cache.impl.TimedCache;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Vector;

@Component
public class LoginFilter extends OncePerRequestFilter {
    private TimedCache<String, Object> timedCache = CacheUtil.newTimedCache(1000 * 60 * 60 * 24 * 2);

    public TimedCache<String, Object> getTimedCache() {
        return timedCache;
    }
    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        String uri = httpServletRequest.getServletPath();
        if (SecurityContextHolder.getContext().getAuthentication() instanceof OAuth2Authentication) {
            OAuth2Authentication authentication = (OAuth2Authentication) SecurityContextHolder.getContext().getAuthentication();
            if (authentication != null && authentication.isAuthenticated() && authentication.getDetails() instanceof OAuth2AuthenticationDetails) {
                OAuth2AuthenticationDetails oAuth2AuthenticationDetails = (OAuth2AuthenticationDetails) authentication.getDetails();
                String clientId = authentication.getOAuth2Request().getClientId();
                String username = String.valueOf(authentication.getPrincipal());
                String key = clientId + "_" + username;
                if (timedCache.containsKey(key)) {
                    Vector<String> sessions = (Vector<String>) timedCache.get(key);
                    if (!sessions.contains(httpServletRequest.getSession().getId())) {
                        sessions.add(httpServletRequest.getSession().getId());
                        timedCache.put(key, sessions);
                    }
                } else {
                    Vector<String> sessions = new Vector<String>();
                    sessions.add(httpServletRequest.getSession().getId());
                    timedCache.put(key, sessions);
                }
            }
        }
        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }
}