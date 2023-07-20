package com.isteer.services;

import java.util.List;
import java.util.Map;

import com.isteer.module.EndPoint;
import com.isteer.module.User;
import com.isteer.service.impl.AddressResponse;
import com.isteer.service.impl.AddressesResponse;
import com.isteer.service.impl.AlternativeReturnUser;
import com.isteer.service.impl.EndPointResponse;
import com.isteer.service.impl.UserResponse;

public interface UserService {

	
	public UserResponse addUser(User user);
	public AlternativeReturnUser updateUser(User user);
	public Map<String,Object> deleteUserById(Integer userId);
	public UserResponse getUserById(Integer userId);
	public List<Map<String, Object>> getAllUser();
	public User getUserByUserName(String userName);
	public String grantPermission(User user);
	public AddressesResponse getAddressByUserId(Integer userId);
	public AddressResponse getAddressByUserIdAndAddressId(Integer userId,Integer addressId);
	public EndPointResponse addNewEndPoint(EndPoint endPoint);
	public EndPointResponse updateEndPointAccess(EndPoint endPoint);
	public List<EndPoint> getAllEndPointDetails();
	
}
