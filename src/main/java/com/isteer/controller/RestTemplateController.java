package com.isteer.controller;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import com.isteer.jwt.token.JwtRequest;
import com.isteer.module.User;

@RestController
@RequestMapping("/RestTemplate")
public class RestTemplateController {

	private RestTemplate restTemplate = new RestTemplate();
	private HttpHeaders headers = new HttpHeaders();

	public <T> ResponseEntity<T> makeRequest(String url, HttpMethod method, Object body, HttpHeaders headers,
			Class<T> responseType) {
		HttpEntity<Object> httpEntity = new HttpEntity<>(body, headers);
		return restTemplate.exchange(url, method, httpEntity, responseType);
	}

	@PostMapping("/authenticate")
	public ResponseEntity<Object> authenticate(@RequestBody JwtRequest jwtRequest) {
		try {
			headers.setContentType(MediaType.APPLICATION_JSON);
			return makeRequest(ExistingUrl.AUTHENTICATEURL, HttpMethod.POST, jwtRequest, headers, Object.class);
		} catch (HttpClientErrorException e) {
			return new ResponseEntity<>(e.getResponseBodyAs(Object.class), e.getStatusCode());
		}
	}

	@PostMapping("/addUser")
	public ResponseEntity<Object> addUser(@RequestBody User user) {
		try {
			headers.setContentType(MediaType.APPLICATION_JSON);
			return makeRequest(ExistingUrl.CREATEURL, HttpMethod.POST, user, headers, Object.class);
		} catch (HttpClientErrorException e) {
			return new ResponseEntity<>(e.getResponseBodyAs(Object.class), e.getStatusCode());
		}
	}

	@GetMapping("/getUserById/{id}")
	public ResponseEntity<Object> getUserById(@PathVariable int id, @RequestHeader String authorization) {
		try {
			headers.add("Authorization", authorization);
			return makeRequest(ExistingUrl.GETUSERBYID + id, HttpMethod.GET, null, headers, Object.class);
		} catch (HttpClientErrorException e) {
			return new ResponseEntity<>(e.getResponseBodyAs(Object.class), e.getStatusCode());
		}
	}

	@PutMapping("/updateUserById")
	public ResponseEntity<Object> updateUser(@RequestBody User user, @RequestHeader String authorization) {
		try {
			headers.setContentType(MediaType.APPLICATION_JSON);
			headers.add("Authorization", authorization);
			return makeRequest(ExistingUrl.UPDATEURL, HttpMethod.PUT, user, headers, Object.class);
		} catch (HttpClientErrorException e) {
			return new ResponseEntity<>(e.getResponseBodyAs(Object.class), e.getStatusCode());
		}
	}

	@DeleteMapping("/deleteUserById/{id}")
	public ResponseEntity<Object> deleteUserById(@PathVariable int id, @RequestHeader String authorization) {
		try {
			headers.setContentType(MediaType.APPLICATION_JSON);
			headers.add("Authorization", authorization);
			return makeRequest(ExistingUrl.DELETEUSERBYID + id, HttpMethod.DELETE, null, headers, Object.class);
		} catch (HttpClientErrorException e) {
			return new ResponseEntity<>(e.getResponseBodyAs(Object.class), e.getStatusCode());
		}

	}
}
