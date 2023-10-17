package com.in28minutes.learnspringsecurity.resources;

import java.util.Arrays;
import java.util.List;

import javax.annotation.security.RolesAllowed;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TodoResource {
	
	private Logger logger = LoggerFactory.getLogger(getClass());

	private static final List<Todo> TODOS_LIST = 
			Arrays.asList(new Todo("in28minutes", "Learn AWS"),
					new Todo("in28minutes", "Get AWS Certified"));

	@GetMapping("/todos")
	public List<Todo> retrieveAllTodos() {
		return TODOS_LIST;
	}

	@GetMapping("/users/{username}/todos")
	//role is configured using  UserDetailsService. and other condition is Username should be in28minutes
	//localhost:8080/users/abc/todos  will fail & localhost:8080/users/in28minutes/todos will pass
	//PreAuthorize is basically checking whether the username what we are providing in request URL
	//is matching with the authentication  & also the USER Role 
	@PreAuthorize("hasRole('USER') and #username == authentication.name")
	
	//Return user name should be in28minutes.Change this from todo List .you will get 403 response
	@PostAuthorize("returnObject.username == 'in28minutes'")
	
	//configured using UserDetailsService.Only users with ADMIN & USER Roles Are allowed 
	@RolesAllowed({"ADMIN", "USER"}) 
	
	//configured using UserDetailsService
	//This is checking the Authority not role
	//@Secured({"ROLE_ADMIN1", "ROLE_USER1"}) API will return 403 if we configure like this.
	@Secured({"ROLE_ADMIN", "ROLE_USER"})	 

	public Todo retrieveTodosForSpecificUser(@PathVariable String username) {
		return TODOS_LIST.get(0);
	}

	@PostMapping("/users/{username}/todos")
	public void createTodoForSpecificUser(@PathVariable String username
			, @RequestBody Todo todo) {
		logger.info("Create {} for {}", todo, username);
	}

}

