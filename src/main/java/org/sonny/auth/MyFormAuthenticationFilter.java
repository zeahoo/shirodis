package org.sonny.auth;

import java.util.Collection;
import java.util.LinkedHashMap;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class MyFormAuthenticationFilter extends FormAuthenticationFilter {


  private static final Logger log = LoggerFactory.getLogger(MyFormAuthenticationFilter.class);

  @Override
  protected boolean executeLogin(final ServletRequest request, final ServletResponse response)
      throws Exception {
    final AuthenticationToken token = createToken(request, response);
    if (token == null) {
      String msg =
          "createToken method implementation returned null. A valid non-null AuthenticationToken"
              + "must be created in order to execute a login attempt.";
      throw new IllegalStateException(msg);
    }
    try {
      // Stop session fixation issues.
      // https://issues.apache.org/jira/browse/SHIRO-170
      final Subject subject = getSubject(request, response);
      Session session = subject.getSession();
      String old_id = (String) session.getId();
      // Store the attributes so we can copy them to the new session after auth.
      final LinkedHashMap<Object, Object> attributes = new LinkedHashMap<Object, Object>();
      final Collection<Object> keys = session.getAttributeKeys();
      for (Object key : keys) {
        final Object value = session.getAttribute(key);
        if (value != null) {
          attributes.put(key, value);
        }
      }
      session.stop();

      subject.login(token);
      // Restore the attributes.
      session = subject.getSession();
      log.debug("OWASP session fixation  from " + old_id + " to " + session.getId());
      for (final Object key : attributes.keySet()) {
        session.setAttribute(key, attributes.get(key));
      }
      return onLoginSuccess(token, subject, request, response);
    } catch (AuthenticationException e) {
      return onLoginFailure(token, e, request, response);
    }
  }
}
