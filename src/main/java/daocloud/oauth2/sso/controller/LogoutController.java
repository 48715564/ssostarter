package daocloud.oauth2.sso.controller;

import daocloud.oauth2.sso.filter.LoginFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import java.util.Vector;

@RestController
@RequestMapping("/syslogout")
public class LogoutController {
    @Autowired
    SessionRegistry sessionRegistry;
    @Autowired
    LoginFilter loginFilter;
    @RequestMapping(method = RequestMethod.GET)
    public void logout(String clientId,String username) {
        String key = clientId+"_"+username;
        Vector<String> sessions = (Vector<String>) loginFilter.getTimedCache().get(key);
        for(String session:sessions){
            SessionInformation sessionInformation = sessionRegistry.getSessionInformation(session);
            if(sessionInformation!=null&&!sessionInformation.isExpired()){
                sessionInformation.expireNow();
//                sessionRegistry.removeSessionInformation(session);
            }
        }
        loginFilter.getTimedCache().remove(key);
//        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
//        if (auth != null){
//            new SecurityContextLogoutHandler().logout(request, response, auth);
//        }
    }
}
