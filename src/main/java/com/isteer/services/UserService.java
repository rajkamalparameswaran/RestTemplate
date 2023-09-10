package com.isteer.services;

import java.sql.SQLException;
import java.util.List;
import java.util.Map;

import com.isteer.module.EndPoint;
import com.isteer.module.User;
import com.isteer.service.impl.AddressResponse;
import com.isteer.service.impl.AddressesResponse;
import com.isteer.service.impl.EndPointResponse;
import com.isteer.service.impl.UserResponse;

public interface UserService {

	public UserResponse addUser(User user);

	public UserResponse updateUser(User user);

	public Map<String, Object> deleteUserById(Integer userId);

	public UserResponse getUserById(Integer userId);

	public List<User> getAllUser();

	public User getUserByUserName(String userName);

	public String grantPermission(User user);

	public AddressesResponse getAddressByUserId(Integer userId);

	public AddressResponse getAddressByUserIdAndAddressId(Integer userId, Integer addressId);

	public EndPointResponse addNewEndPoint(EndPoint endPoint);

	public EndPointResponse updateEndPointAccess(EndPoint endPoint);

	public List<EndPoint> getAllEndPointDetails();
	
	public void addValidToken(String jwt, String issuedTime, String expiredTime) throws SQLException;
	
	public void deleteValidToken(String jwt) throws SQLException;

}
