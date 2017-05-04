package io.reactivesw.gateway.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.List;

/**
 * Auth filter config.
 */
@Configuration
@ConfigurationProperties(prefix = "auth.ignored")
@Data
public class AuthFilterConfig {

  /**
   * Ignored hosts that do not need to check auth.
   */
  private List<String> hosts = new ArrayList<>();

}
