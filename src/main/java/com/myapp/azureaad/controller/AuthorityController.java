package com.myapp.azureaad.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class AuthorityController {
	@GetMapping("Admin")
	@ResponseBody
	@PreAuthorize("hasAuthority('APPROLE_Admin')")
	public String Admin() {
		return "Admin message";
	}
}
