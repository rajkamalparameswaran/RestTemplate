package com.isteer.service.impl;

import java.security.Principal;
import java.sql.SQLException;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.isteer.dao.UserDao;
import com.isteer.exception.SqlQueryException;
import com.isteer.exception.UserIdNotFoundException;
import com.isteer.message.properties.FailedMessage;
import com.isteer.message.properties.SuccessMessage;
import com.isteer.module.EndPoint;
import com.isteer.module.User;
import com.isteer.services.UserService;
import com.isteer.statuscode.StatusCode;

@Service
@Transactional
public class UserServiceImpl implements UserService {

	private static final Logger AUDITLOG = LogManager.getLogger("AuditLogs");

	public static final String LOGMSG = "{} : Id : {}";

	@Autowired
	SuccessMessage successMsg;
	@Autowired
	FailedMessage failedMsg;

	@Autowired
	UserDao userDao;

	@Autowired
	Principal principal;

	public void userIdFoundAndExceptionThrower(Integer userId) {
		boolean idFound;
		try {
			idFound = !userDao.isIdFound(userId);
		} catch (SQLException e) {
			throw new SqlQueryException(StatusCode.SQLEXCEPTIONCODE.getCode(), failedMsg.getInvalidSqlQuery(),
					Arrays.asList(e.getLocalizedMessage()));
		}
		if (idFound) {
			List<String> exception = new ArrayList<>();
			exception.add(failedMsg.getUserIdNotFound());
			AUDITLOG.info(LOGMSG, failedMsg.getUserIdNotFound(), userId);
			throw new UserIdNotFoundException(StatusCode.USERIDNOTFOUND.getCode(), failedMsg.getUserIdNotFound(),
					exception);
		}
	}

	@Override
	public UserResponse addUser(User user) {
		List<String> exceptions = new ArrayList<>();
		Integer userId = null;
		exceptions.addAll(getErrorList(user));
		if (exceptions.isEmpty()) {
			try {
				userId = userDao.addUser(user);
				user.setUserId(userId);
				userDao.addAddresses(user.getUserAddresses(), userId);
				userDao.addRoles(user.getUserRoles(), userId);
				userDao.addPrivileges(userId);
				AUDITLOG.info(LOGMSG, successMsg.getAccountCreated(), userId);
				return new UserResponse(StatusCode.SUCESSCODE.getCode(), successMsg.getAccountCreated(),
						userDao.getUserByUserName(user.getUserName()));
			} catch (SQLException e) {
				throw new SqlQueryException(StatusCode.SQLEXCEPTIONCODE.getCode(), failedMsg.getInvalidSqlQuery(),
						Arrays.asList(e.getLocalizedMessage()));
			} catch (Exception e) {
				exceptions.add(e.getLocalizedMessage());
				AUDITLOG.error(e.getMessage());
				throw new SqlQueryException(StatusCode.ACCOUNTCREATEDFAILED.getCode(),
						failedMsg.getAccountCreationFailed(), exceptions);
			}
		} else {
			AUDITLOG.info(failedMsg.getNotValidData());
			throw new SqlQueryException(StatusCode.ACCOUNTCREATEDFAILED.getCode(), failedMsg.getNotValidData(),
					exceptions);
		}
	}

	@Override
	public UserResponse updateUser(User user) {
		userIdFoundAndExceptionThrower(user.getUserId());
		try {
			if (userDao.toCheckDuplicateUserName(user.getUserName(), user.getUserId()) != 0
					|| userDao.toCheckDuplicateUserEmail(user.getUserEmail(), user.getUserId()) != 0) {
				throw new SQLException(failedMsg.getNameOrEmailAlreadyExist());
			}
			User tempUser = userDao.getUserById(user.getUserId());
			if (principal.toString().contains("ADMIN")) {
				userDao.updateUserByAdmin(user);
				updateListOfAddress(user.getUserAddresses(), user.getUserId());
				updateListOfRoles(user.getUserRoles(), user.getUserId());
				updateListOfPrivileges(user.getPrivileges(), user.getUserId());
				AUDITLOG.info(LOGMSG, successMsg.getAccountUpdated(), user.getUserId());
				return new UserResponse(StatusCode.SUCESSCODE.getCode(), successMsg.getAccountUpdated(),
						userDao.getUserById(user.getUserId()));
			} else {
				if (tempUser.getUserName().equals(principal.getName())) {
					userDao.updateUserByUser(user);
					updateListOfAddress(user.getUserAddresses(), user.getUserId());
					AUDITLOG.info(LOGMSG, successMsg.getAccountUpdated(), user.getUserId());
					return new UserResponse(StatusCode.SUCESSCODE.getCode(), successMsg.getAccountUpdated(),
							userDao.getUserById(user.getUserId()));
				} else {
					throw new AccessDeniedException("You Cannot Update that User Details");
				}
			}
		} catch (SQLException e) {
			throw new SqlQueryException(StatusCode.SQLEXCEPTIONCODE.getCode(), failedMsg.getInvalidSqlQuery(),
					Arrays.asList(e.getLocalizedMessage()));
		} catch (Exception e) {
			AUDITLOG.error(LOGMSG, e.getMessage(), user.getUserId());
			throw new SqlQueryException(StatusCode.ACCOUNTUPDATEDFAILED.getCode(), failedMsg.getUserUpdationFailed(),
					Arrays.asList(e.getLocalizedMessage()));
		}
	}

	public void updateListOfAddress(List<String> addresses, int userId) throws SQLException {
		if (addresses != null) {
			userDao.deleteAddressById(userId);
			userDao.addAddresses(addresses, userId);
		}
	}

	public void updateListOfRoles(List<String> roles, int userId) throws SQLException {
		if (roles != null) {
			userDao.deleteRolesById(userId);
			userDao.addRoles(roles, userId);
		}
	}

	public void updateListOfPrivileges(List<String> privileges, int userId) throws SQLException {
		if (privileges != null) {
			userDao.deletePrivilegesById(userId);
			userDao.addPrivileges(privileges, userId);
		}
	}

	@Override
	public Map<String, Object> deleteUserById(Integer userId) {
		userIdFoundAndExceptionThrower(userId);
		try {
			userDao.deleteRolesById(userId);
			userDao.deleteAddressById(userId);
			userDao.deletePrivilegesById(userId);
			userDao.deleteUserById(userId);
			AUDITLOG.info(LOGMSG, successMsg.getAccountDeleted(), userId);
			Map<String, Object> response = new HashMap<>();
			response.put("UserId", userId);
			response.put("StatusCode", StatusCode.SUCESSCODE.getCode());
			response.put("Message", successMsg.getAccountDeleted());
			return response;
		} catch (SQLException e) {
			throw new SqlQueryException(StatusCode.SQLEXCEPTIONCODE.getCode(), failedMsg.getInvalidSqlQuery(),
					Arrays.asList(e.getLocalizedMessage()));
		}
	}

	@Override
	public UserResponse getUserById(Integer userId) {
		userIdFoundAndExceptionThrower(userId);
		try {
			User user = userDao.getUserById(userId);
			if (user == null) {
				AUDITLOG.info(failedMsg.getNotValidData());
				throw new UserIdNotFoundException(StatusCode.USERIDNOTFOUND.getCode(),
						failedMsg.getDataFetchProcssFailed(), Arrays.asList(failedMsg.getNoDataFound()));
			}
			AUDITLOG.info(LOGMSG, successMsg.getAccountFetched(), userId);
			return new UserResponse(StatusCode.SUCESSCODE.getCode(), successMsg.getAccountFetched(), user);
		} catch (SQLException e) {
			throw new SqlQueryException(StatusCode.SQLEXCEPTIONCODE.getCode(), failedMsg.getInvalidSqlQuery(),
					Arrays.asList(e.getLocalizedMessage()));
		}
	}

	@Override
	public List<User> getAllUser() {
		try {
			AUDITLOG.info(successMsg.getAccountFetched());
			List<User> users = userDao.getAllUsers();
			if (users.isEmpty()) {
				AUDITLOG.info(failedMsg.getNoDataFound());
				throw new UserIdNotFoundException(StatusCode.ACCOUNTFETCHINGFAILED.getCode(),
						failedMsg.getDataFetchProcssFailed(), Arrays.asList(failedMsg.getNoDataFound()));
			}
			return users;
		} catch (SQLException e) {
			throw new SqlQueryException(StatusCode.SQLEXCEPTIONCODE.getCode(), failedMsg.getInvalidSqlQuery(),
					Arrays.asList(e.getLocalizedMessage()));
		}
	}

	@Override
	public User getUserByUserName(String userName) {
		try {
			User user = userDao.getUserByUserName(userName);
			if (user == null) {
				AUDITLOG.info(failedMsg.getNotValidData());
				throw new UserIdNotFoundException(StatusCode.USERIDNOTFOUND.getCode(),
						failedMsg.getDataFetchProcssFailed(), Arrays.asList(failedMsg.getInvalidName()));
			}
			AUDITLOG.info(LOGMSG, successMsg.getAccountFetched(), user.getUserId());
			return user;
		} catch (SQLException e) {
			AUDITLOG.error(e.getLocalizedMessage());
			throw new SqlQueryException(StatusCode.SQLEXCEPTIONCODE.getCode(), failedMsg.getInvalidSqlQuery(),
					Arrays.asList(e.getLocalizedMessage()));
		}

	}

	@Override
	public String grantPermission(User user) {
		userIdFoundAndExceptionThrower(user.getUserId());
		try {
			userDao.deletePrivilegesById(user.getUserId());
			userDao.addPrivileges(user.getPrivileges(), user.getUserId());
			String message = MessageFormat.format("Permission provided to the userId :{0}", user.getUserId());
			AUDITLOG.info(message);
			return message;
		} catch (SQLException e) {
			throw new SqlQueryException(StatusCode.SQLEXCEPTIONCODE.getCode(), failedMsg.getInvalidSqlQuery(),
					Arrays.asList(e.getLocalizedMessage()));
		} catch (Exception e) {
			AUDITLOG.error(LOGMSG, e.getLocalizedMessage(), user.getUserId());
			throw new SqlQueryException(StatusCode.ACCOUNTCREATEDFAILED.getCode(), failedMsg.getProcessFailed(),
					Arrays.asList(e.getMessage()));
		}
	}

	@Override
	public AddressesResponse getAddressByUserId(Integer userId) {
		List<String> exception = new ArrayList<>();
		userIdFoundAndExceptionThrower(userId);
		try {
			List<String> addresses = userDao.getAddressByUserId(userId);
			AUDITLOG.info(LOGMSG, successMsg.getAccountFetched(), userId);
			return new AddressesResponse(StatusCode.SUCESSCODE.getCode(), successMsg.getAccountFetched(), addresses);
		} catch (SQLException e) {
			throw new SqlQueryException(StatusCode.SQLEXCEPTIONCODE.getCode(), failedMsg.getInvalidSqlQuery(),
					Arrays.asList(e.getLocalizedMessage()));
		} catch (Exception e) {
			exception.add(e.getMessage());
			AUDITLOG.error(LOGMSG, e.getLocalizedMessage(), userId);
			throw new SqlQueryException(StatusCode.ACCOUNTFETCHINGFAILED.getCode(),
					failedMsg.getDataFetchProcssFailed(), exception);
		}
	}

	@Override
	public AddressResponse getAddressByUserIdAndAddressId(Integer userId, Integer addressId) {
		List<String> exception = new ArrayList<>();
		userIdFoundAndExceptionThrower(userId);
		try {
			if (userDao.addressIdFounder(addressId) == null) {
				exception.add(failedMsg.getUserIdNotFound());
			}
		} catch (SQLException e) {
			throw new SqlQueryException(StatusCode.SQLEXCEPTIONCODE.getCode(), failedMsg.getInvalidSqlQuery(),
					Arrays.asList(e.getLocalizedMessage()));
		}
		if (!exception.isEmpty()) {
			throw new UserIdNotFoundException(StatusCode.USERIDNOTFOUND.getCode(), failedMsg.getDataFetchProcssFailed(),
					exception);
		}
		try {
			String address = userDao.getAddressByUserIdAndAddressId(userId, addressId);
			if (address == null) {
				String msg = "userId and address id not match";
				exception.add(msg);
				AUDITLOG.info(msg);
				throw new UserIdNotFoundException(StatusCode.ACCOUNTFETCHINGFAILED.getCode(),
						failedMsg.getDataFetchProcssFailed(), exception);
			}
			return new AddressResponse(StatusCode.SUCESSCODE.getCode(), successMsg.getAccountFetched(), address);
		} catch (UserIdNotFoundException e) {
			throw e;
		} catch (Exception e) {
			exception.add(e.getMessage());
			AUDITLOG.error(e.getLocalizedMessage());
			throw new SqlQueryException(StatusCode.ACCOUNTFETCHINGFAILED.getCode(),
					failedMsg.getDataFetchProcssFailed(), exception);
		}
	}

	@Override
	public EndPointResponse addNewEndPoint(EndPoint endPoint) {
		List<String> exception = new ArrayList<>();
		if (endPoint.getEndPointName() == null || endPoint.getAuthorities() == null) {
			exception.add(failedMsg.getNotValidData());
		}
		if (exception.isEmpty()) {
			try {
				Integer endPointId = userDao.addEndPoint(endPoint);
				endPoint.setEndPointId(endPointId);
				userDao.addAuthorization(endPoint.getAuthorities(), endPointId);
				AUDITLOG.info(LOGMSG, successMsg.getEndPointAdded(), endPointId);
				return new EndPointResponse(StatusCode.SUCESSCODE.getCode(), successMsg.getEndPointAdded(), endPoint);
			} catch (SQLException e) {
				throw new SqlQueryException(StatusCode.SQLEXCEPTIONCODE.getCode(), failedMsg.getInvalidSqlQuery(),
						Arrays.asList(e.getLocalizedMessage()));
			} catch (Exception e) {
				AUDITLOG.error(e.getLocalizedMessage());
				throw new SqlQueryException(StatusCode.ENDPOINTACESSUPDATEDFAILED.getCode(),
						failedMsg.getEndPointCannotAdded(), Arrays.asList(e.getMessage()));
			}
		} else {
			AUDITLOG.info(failedMsg.getNotValidData());
			throw new SqlQueryException(StatusCode.ENDPOINTADDEDFAILED.getCode(), failedMsg.getEndPointCannotAdded(),
					exception);
		}
	}

	@Override
	public EndPointResponse updateEndPointAccess(EndPoint endPoint) {
		List<String> exception = new ArrayList<>();
		String endPointName = null;
		try {
			endPointName = userDao.endPointIdFounder(endPoint.getEndPointId());
		} catch (SQLException e) {
			throw new SqlQueryException(StatusCode.SQLEXCEPTIONCODE.getCode(), failedMsg.getInvalidSqlQuery(),
					Arrays.asList(e.getLocalizedMessage()));
		}
		endPoint.setEndPointName(endPointName);
		if (endPointName == null) {
			exception.add(failedMsg.getUserIdNotFound());
			AUDITLOG.info(LOGMSG, failedMsg.getUserIdNotFound(), endPoint.getEndPointId());
			throw new UserIdNotFoundException(StatusCode.USERIDNOTFOUND.getCode(), failedMsg.getProcessFailed(),
					exception);
		}
		if (endPoint.getAuthorities() == null) {
			exception.add(failedMsg.getNotValidData());
		}
		if (!exception.isEmpty()) {
			AUDITLOG.info(LOGMSG, failedMsg.getNotValidData(), endPoint.getEndPointId());
			throw new SqlQueryException(StatusCode.ENDPOINTACESSUPDATEDFAILED.getCode(),
					failedMsg.getUserUpdationFailed(), exception);
		}
		try {
			userDao.deleteAuthorization(endPoint.getEndPointId());
			userDao.addAuthorization(endPoint.getAuthorities(), endPoint.getEndPointId());
			AUDITLOG.info(LOGMSG, successMsg.getAccountUpdated(), endPoint.getEndPointId());
			return new EndPointResponse(StatusCode.SUCESSCODE.getCode(), successMsg.getAccountUpdated(), endPoint);
		} catch (SQLException e) {
			throw new SqlQueryException(StatusCode.SQLEXCEPTIONCODE.getCode(), failedMsg.getInvalidSqlQuery(),
					Arrays.asList(e.getLocalizedMessage()));
		} catch (Exception e) {
			exception.add(e.getMessage());
			AUDITLOG.error(e.getLocalizedMessage());
			throw new SqlQueryException(StatusCode.ENDPOINTACESSUPDATEDFAILED.getCode(),
					failedMsg.getUserUpdationFailed(), exception);
		}
	}

	@Override
	public List<EndPoint> getAllEndPointDetails() {
		try {

			List<EndPoint> endPoints = userDao.getAllEndPointDetails();
			if (endPoints.isEmpty()) {
				AUDITLOG.info(failedMsg.getNoDataFound());
				throw new UserIdNotFoundException(StatusCode.ACCOUNTFETCHINGFAILED.getCode(),
						failedMsg.getDataFetchProcssFailed(), Arrays.asList(failedMsg.getNoDataFound()));
			}
			AUDITLOG.info(successMsg.getAccountFetched());
			return endPoints;
		} catch (SQLException e) {
			throw new SqlQueryException(StatusCode.SQLEXCEPTIONCODE.getCode(), failedMsg.getInvalidSqlQuery(),
					Arrays.asList(e.getLocalizedMessage()));
		}
	}

	public List<String> getErrorList(User user) {
		List<String> exceptions = new ArrayList<>();
		if ((user.getUserName() == null) || (user.getUserFullName() == null) || (user.getUserEmail() == null)
				|| (user.getUserPassword() == null) || (user.getUserAddresses() == null)
				|| (user.getUserRoles() == null)) {
			exceptions.add(failedMsg.getNotValidData());
		} else {
			if (user.getUserAddresses().isEmpty()) {
				exceptions.add(failedMsg.getEmptyAddress());
			}
			if (!(user.getUserEmail().length() > 5 && user.getUserEmail().length() < 20)) {
				exceptions.add(failedMsg.getEmailLengthInvalid());
			}
			if (user.getUserRoles().isEmpty()) {
				exceptions.add(failedMsg.getEmptyRoles());
			}
			if (!(user.getUserName().length() > 3 && user.getUserName().length() <= 10)) {
				exceptions.add(failedMsg.getNameLengthInvalid());
			}
			try {
				if (userDao.toCheckDuplicateUserName(user.getUserName(), user.getUserId()) != 0
						|| userDao.toCheckDuplicateUserEmail(user.getUserEmail(), user.getUserId()) != 0) {
					exceptions.add(failedMsg.getNameOrEmailAlreadyExist());
				}
			} catch (SQLException e) {
				throw new SqlQueryException(StatusCode.SQLEXCEPTIONCODE.getCode(), failedMsg.getInvalidSqlQuery(),
						Arrays.asList(e.getLocalizedMessage()));
			}
		}
		return exceptions;
	}

	@Override
	public void addValidToken(String jwt, String issuedTime, String expiredTime) throws SQLException {
		userDao.addValidToken(jwt, issuedTime, expiredTime);
	}

	@Override
	public void deleteValidToken(String jwt) {
		try {
			userDao.deleteValidToken(jwt);
		} catch (Exception e) {
			throw new SqlQueryException(StatusCode.SQLEXCEPTIONCODE.getCode(), failedMsg.getInvalidSqlQuery(),
					Arrays.asList(e.getLocalizedMessage()));
		}
	}

}
