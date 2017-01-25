/**
 * Copyright (c) 2015-2016 Bosch Software Innovations GmbH and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 *
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * The Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 * Bosch Software Innovations GmbH - Please refer to git log
 */
package org.eclipse.vorto.repository.web;

import java.security.Principal;
import java.util.Map;

import javax.validation.Valid;

import org.eclipse.vorto.repository.model.Role;
import org.eclipse.vorto.repository.model.User;
import org.eclipse.vorto.repository.service.IUserRepository;
import org.jgroups.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;

/**
 * @author Alexander Edelmann - Robert Bosch (SEA) Pte. Ltd.
 */
@Api(value="User Controller", description="REST API to manage User")
@RestController
@RequestMapping(value = "/rest")
public class UserController {

    private final Logger LOGGER = LoggerFactory.getLogger(getClass());
    
	@Autowired
	private IUserRepository userRepository;
//	
//	@Autowired
//	private DefaultTokenServices tokenService;

		
	@ApiOperation(value = "Returns a specified User")
	@ApiResponses(value = { @ApiResponse(code = 404, message = "Not found"), 
							@ApiResponse(code = 200, message = "OK")})
	@RequestMapping(method = RequestMethod.GET,
					value = "/users")
	public ResponseEntity<User> getUser(Principal oauthuser) {
		User user = userRepository.findByUsername(oauthuser.getName());
		if (user != null) {
			return new ResponseEntity<User>(user, HttpStatus.OK);
		} else {
			OAuth2Authentication oauth2user = (OAuth2Authentication)oauthuser;
			UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken)oauth2user.getUserAuthentication();
			Map<String,String> details = (Map<String,String>)token.getDetails();
			user = new User();
			user.setEmail(details.get("email"));
			user.setUsername(details.get("login"));
			user.setHasWatchOnRepository(false);
			user.setRoles(Role.USER);
			user.setFirstName(extractFirstName(details.get("name")));
			user.setLastName(extractLastName(details.get("name")));
			return new ResponseEntity<>(user,HttpStatus.OK);
		}
		
	}
	
	private String extractFirstName(String name) {
		return name.split(" ")[0];
	}
	
	private String extractLastName(String name) {
		if (name.split(" ").length == 2) {
			return name.split(" ")[1];
		} else {
			return null;
		}
	}

	@ApiOperation(value = "Updates user")
	@RequestMapping(method = RequestMethod.PUT,
				value = "/users",
	    		consumes = "application/json")
	public ResponseEntity<Boolean> updateUser(@ApiParam(value = "User", required = true) @RequestBody @Valid User user) {
		this.userRepository.save(user);
		return new ResponseEntity<Boolean>(false, HttpStatus.CREATED);
	}
	
	@RequestMapping(method = RequestMethod.GET,
			value = "/users/token", produces = "application/txt")
	public String generateAccessToken() {
		return UUID.randomUUID().toString();
	}
	
	/* checking uniqueness of specific values
	 */        
	@ApiOperation(value = "Compares an Email-Address with all already existing Email-Addresses")
	@RequestMapping(method = RequestMethod.POST,
    				value = "/users/unique/email")
	public ResponseEntity<Boolean> checkEmailAdressAlreadyExists(@ApiParam(value = "Email-Address", required = true)  @RequestBody String email) {		

    	boolean emailExists = false;
    	if (userRepository.findByEmail(email) == null){
    		 emailExists = false;
		} else {
			 emailExists = true;
		}
    	
		return new ResponseEntity<Boolean>(emailExists, HttpStatus.OK);
	}
    
	@ApiOperation(value = "Compares a username with all already existing usernames")
    @RequestMapping(method = RequestMethod.POST,
					value = "/users/unique/username",
					consumes = "application/json")
	public ResponseEntity<Boolean> checkUsernameAlreadyExists(@ApiParam(value = "Username", required = true)  @RequestBody String username) {		
    	
    	boolean userExists = false;
		
    	if (userRepository.findByUsername(username.toLowerCase()) == null){
			userExists = false;
		} else {
			
			userExists = true;
		}
    	
    	LOGGER.debug("username exists: "+userExists);
		return new ResponseEntity<Boolean>(userExists, HttpStatus.OK);	
	}
	
}