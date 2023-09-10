package com.isteer.controller;

import java.sql.SQLException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.isteer.exception.SqlQueryException;
import com.isteer.exception.UserIdNotFoundException;
import com.isteer.jwt.token.JwtRequest;
import com.isteer.jwt.token.JwtRsponse;
import com.isteer.jwt.token.JwtUtil;
import com.isteer.message.properties.FailedMessage;
import com.isteer.message.properties.SuccessMessage;
import com.isteer.module.EndPoint;
import com.isteer.module.User;
import com.isteer.service.impl.AddressResponse;
import com.isteer.service.impl.AddressesResponse;
import com.isteer.service.impl.EndPointResponse;
import com.isteer.service.impl.UserResponse;
import com.isteer.services.UserService;
import com.isteer.statuscode.StatusCode;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@RestController
public class UserController {

	@Autowired
	private FailedMessage failedMsg;

	@Autowired
	private SuccessMessage sucessMsg;

	@Autowired
	UserService service;

	@Autowired
	AuthenticationManager authenticationManager;

	@Autowired
	JwtUtil util;

	@Autowired
	UserDetailsService userDetailsService;

	private static final Logger AUDITLOG = LogManager.getLogger("AuditLogs");

	// This API is used to add new user in DB.
	// we need to provide valid data
	// (userName,userFullName,userEmail,userPassword,userAddresses,userRoles).

	@PostMapping("/addUser")
	public ResponseEntity<UserResponse> addUser(@RequestBody User user) {
		return new ResponseEntity<>(service.addUser(user), HttpStatus.CREATED);
	}

	// This API is used to update the existing user data
	// we need to provide valid
	// data(userId,userName,userFullName,userEmail,userPassword,
	// userAddresses,userRoles,privileges,accountNonExpired,accountNonLocked,credentialsNonExpired,enabled).
	// In order to access the API we need provide Bearer token

	@PutMapping("/updateUser")
	public ResponseEntity<UserResponse> updateUser(@RequestBody User user) {
		return new ResponseEntity<>(
				service.updateUser(user),
				HttpStatus.ACCEPTED);
	}

	// This API provide permission to particular user
	// we need to provide valid data (userId,privileges).
	// In order to access the API we need provide Bearer token

	@PutMapping("/grandPermissions")
	public ResponseEntity<String> grantPermission(@RequestBody User user) {
		return new ResponseEntity<>(service.grantPermission(user), HttpStatus.ACCEPTED);
	}

	// This API is used to delete the particular user based on Id
	// In order to access the API we need provide Bearer token

	@DeleteMapping("/deleteUserById/{userId}")
	public ResponseEntity<Map<String, Object>> updateUser(@PathVariable Integer userId) {
		return new ResponseEntity<>(service.deleteUserById(userId), HttpStatus.OK);
	}

	// This API is used to get particular user data based on userId
	// In order to access the API we need provide Bearer token

	@GetMapping("/getUserById/{userId}")
	public ResponseEntity<UserResponse> getUserById(@PathVariable Integer userId) {
		return new ResponseEntity<>(service.getUserById(userId), HttpStatus.FOUND);
	}

	// This API is used to get All the user
	// In order to access the API we need provide Bearer token

	@GetMapping("/getAllUsers")
	public ResponseEntity<List<User>> getAllUser() {
		return new ResponseEntity<>(service.getAllUser(), HttpStatus.FOUND);
	}

	// This API is used to get particular user data based on userName
	// In order to access the API we need provide Bearer token

	@GetMapping("/getUserByName/{userName}")
	public ResponseEntity<User> getUserByName(@PathVariable String userName) {
		return new ResponseEntity<>(service.getUserByUserName(userName), HttpStatus.FOUND);
	}

	// This API is used to authenticate the user
	// we need to provide (userId,password)

	@PostMapping("/authenticate")
	public ResponseEntity<JwtRsponse> authenticat(@RequestBody JwtRequest request) {
		try {
			authenticationManager.authenticate(
					new UsernamePasswordAuthenticationToken(request.getUserName(), request.getUserPassword()));
			UserDetails userDetails = userDetailsService.loadUserByUsername(request.getUserName());
			String jwt = util.generateToken(userDetails);
			service.addValidToken(jwt, getMySqlTimeFormat(util.extractIssuedAt(jwt)),
					getMySqlTimeFormat(util.extractExpiration(jwt)));
			JwtRsponse jwtRsponse = new JwtRsponse(jwt, StatusCode.SUCESSCODE.getCode(), sucessMsg.getLoginSucess());
			return new ResponseEntity<>(jwtRsponse, HttpStatus.CREATED);
		} catch (SQLException e) {
			throw new SqlQueryException(StatusCode.SQLEXCEPTIONCODE.getCode(), failedMsg.getInvalidSqlQuery(),
					Arrays.asList(e.getLocalizedMessage()));
		} catch (Exception e) {
			List<String> exception = new ArrayList<>();
			exception.add(failedMsg.getWrongUserIdOrPassword());
			AUDITLOG.info(failedMsg.getWrongUserIdOrPassword());
			throw new UserIdNotFoundException(StatusCode.USERAUTHENTICATIONFAILED.getCode(), failedMsg.getLoginFailed(),
					exception);
		}
	}

	@GetMapping("/getAddressByUserId/{userId}")
	public ResponseEntity<AddressesResponse> getGetAddressById(@PathVariable Integer userId) {
		return new ResponseEntity<>(service.getAddressByUserId(userId), HttpStatus.FOUND);

	}

	@GetMapping("/getAddressByUserIdAndAddressId/{userId}/{addressId}")
	public ResponseEntity<AddressResponse> getGetAddressById(@PathVariable Integer userId,
			@PathVariable Integer addressId) {
		return new ResponseEntity<>(service.getAddressByUserIdAndAddressId(userId, addressId), HttpStatus.FOUND);
	}

	// This API is used to add a new API in DB
	// In order to access the API we need provide Bearer token

	@PostMapping("/addNewEndPoint")
	public ResponseEntity<EndPointResponse> addNewEndPoint(@RequestBody EndPoint endPoint) {
		return new ResponseEntity<>(service.addNewEndPoint(endPoint), HttpStatus.CREATED);
	}

	// This API is used update the existing endpoint based on endPoint id
	// In order to access the API we need provide Bearer token
	// we need to provide valid data(endPointId,authorities)

	@PutMapping("/updateEndPointByEndPointId")
	public ResponseEntity<EndPointResponse> updateEndPointByEndPointId(@RequestBody EndPoint endPoint) {
		return new ResponseEntity<>(service.updateEndPointAccess(endPoint), HttpStatus.OK);
	}

	// This API is used to get All end poin details
	// In order to access the API we need provide Bearer token

	@GetMapping("/getAllEndPointDetails")
	public ResponseEntity<List<EndPoint>> getAllEndPoint() {
		return new ResponseEntity<>(service.getAllEndPointDetails(), HttpStatus.FOUND);
	}

	@PostMapping("/logOut")
	public ResponseEntity<Map<String, Object>> logOut(HttpServletRequest httpServletRequest,
			HttpServletResponse httpServletResponse) {
		try {
			String jwt = httpServletRequest.getHeader("Authorization").substring(7);
			service.deleteValidToken(jwt);
			Map<String, Object> body = new HashMap<>();
			body.put("StatusCode", 1);
			body.put("Msg", "Logout Sucessfully");
			return new ResponseEntity<>(body, HttpStatus.OK);
		} catch (SQLException e) {
			throw new SqlQueryException(StatusCode.SQLEXCEPTIONCODE.getCode(), failedMsg.getInvalidSqlQuery(),
					Arrays.asList(e.getLocalizedMessage()));
		}
	}

	public String getMySqlTimeFormat(Date date) {
		LocalDateTime localDateTime = date.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();
		DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
		return localDateTime.format(dateTimeFormatter);
	}

}
