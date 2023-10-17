package com.in28minutes.learnspringsecurity.resources;

public class Todo {
	Todo(){
		
	}
	private String username;
	private String description;
	public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
	}
	public String getDescription() {
		return description;
	}
	public void setDescription(String description) {
		this.description = description;
	}
	@Override
	public String toString() {
		return "Todo [username=" + username + ", description=" + description + "]";
	}
	public Todo(String username, String description) {
		super();
		this.username = username;
		this.description = description;
	}
	
	
}
