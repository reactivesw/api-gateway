package io.reactivesw.gateway.filters;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import io.reactivesw.gateway.config.AuthFilterConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;

import static com.netflix.zuul.context.RequestContext.getCurrentContext;

/**
 * Authentication filter for checkout customer's authorization.
 */
@Component
public class AuthenticationPreFilter extends ZuulFilter {


  /**
   * Logger.
   */
  private static final Logger LOG = LoggerFactory.getLogger(AuthenticationPreFilter.class);

  /**
   * RestTemplate.
   */
  private transient RestTemplate restTemplate = new RestTemplate();

  /**
   * Authentication service uri.
   */
  @Value("${authentication.service.uri:http://auth/}")
  private transient String authUri;

  @Autowired
  private AuthFilterConfig config;

  /**
   * Filter type.
   *
   * @return string
   */
  @Override
  public String filterType() {
    // use "pre", so we can check the auth before router to back end services.
    return "pre";
  }

  /**
   * Filter order.
   *
   * @return int
   */
  @Override
  public int filterOrder() {
    // use
    return 6;
  }

  /**
   * Check if we need to run this filter for this request.
   *
   * @return boolean
   */
  @Override
  public boolean shouldFilter() {
    RequestContext ctx = getCurrentContext();
    String host = ctx.getRouteHost().getHost();
    boolean shouldFilter = true;
    if (config.getHosts().contains(host)) {
      shouldFilter = false;
    }
    return shouldFilter;
  }

  /**
   * Run function.
   *
   * @return always return null
   */
  @Override
  public Object run() {
    RequestContext ctx = getCurrentContext();
    HttpServletRequest request = ctx.getRequest();
    String token = request.getHeader("authorization");
    String customerId = checkAuthentication(token);
    if (customerId != null) {
      // if true, then set the customerId to header
      ctx.addZuulRequestHeader("customerId", customerId);
    } else {
      // stop routing and return auth failed.
      ctx.unset();
      ctx.setResponseStatusCode(HttpStatus.UNAUTHORIZED.value());
    }
    return null;
  }


  /**
   * Check the auth status
   *
   * @param tokenString String
   * @return the customer id
   */
  public String checkAuthentication(String tokenString) {
    LOG.debug("Enter. token: {}", tokenString);

    try {
      String token = tokenString.substring(7);
      String uri = authUri + "status?token=" + token;
      LOG.debug("AuthUri: {}", uri);

      String customerId = restTemplate.getForObject(uri, String.class);

      LOG.debug("Exit. customerId: {}", customerId);
      return customerId;
    } catch (RestClientException | NullPointerException ex) {
      LOG.debug("Get customerId from authentication service failed.", ex);
      return null;
    }
  }
}
