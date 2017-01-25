package org.eclipse.vorto.repository.web.security;

import javax.transaction.Transactional;

import org.eclipse.vorto.repository.model.User;
import org.eclipse.vorto.repository.service.IUserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@Transactional
public class UserDetailsServiceImpl implements UserDetailsService {
	
	@Autowired
    private IUserRepository userRepository;
	
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        
    	User user = userRepository.findByUsername(username);
    
        if (user == null) {
            throw new UsernameNotFoundException("No user found with username: "+ username);
        }
        
        boolean enabled = true;
        boolean accountNonExpired = true;
        boolean credentialsNonExpired = true;
        boolean accountNonLocked = true;
               
        return  new org.springframework.security.core.userdetails.User(
        		  user.getUsername(), 
        		  user.getToken(),
        		  enabled, 
        		  accountNonExpired,
        		  credentialsNonExpired, 
        		  accountNonLocked,
        		  AuthorityUtils.createAuthorityList("ROLE_"+user.getRole().toString()));
    }

}
