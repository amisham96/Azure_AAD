package com.myapp.azureaad.controller;

import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import static com.myapp.azureaad.utils.JsonMapper.toJsonString;

@Controller
public class OnDemandClientController {

	@GetMapping("/arm")
	@ResponseBody
	public String arm(@RegisteredOAuth2AuthorizedClient("arm") OAuth2AuthorizedClient armClient) {
		// toJsonString() is just a demo.
		// oAuth2AuthorizedClient contains access_token. We can use this access_token to
		// access resource server.
		return toJsonString(armClient);
	}
}