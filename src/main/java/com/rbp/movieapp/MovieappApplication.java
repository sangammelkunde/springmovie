package com.rbp.movieapp;

import com.rbp.movieapp.models.ERole;
import com.rbp.movieapp.models.Movie;
import com.rbp.movieapp.models.Role;
import com.rbp.movieapp.repository.MovieRepository;
import com.rbp.movieapp.repository.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.mongodb.core.MongoTemplate;

import java.util.ArrayList;
import java.util.List;

@SpringBootApplication

public class MovieappApplication implements CommandLineRunner {

	@Autowired
	private MovieRepository movieRepository;
	@Autowired
	private RoleRepository roleRepository;

	@Autowired
	private MongoTemplate mongoTemplate;


	public static void main(String[] args) {
		SpringApplication.run(MovieappApplication.class, args);
	}

	@Override
	public void run(String... args) throws Exception {
		mongoTemplate.dropCollection("roles");
//		mongoTemplate.dropCollection("ticket");
//		mongoTemplate.dropCollection("users");
		mongoTemplate.dropCollection("movie");

		List<Movie> movies = new ArrayList<>();
		movies.add(new Movie("Dasara", "Miraj", 126, "Book ASAP"));
		movies.add(new Movie("Bhoola", "Miraj", 122, "Book ASAP"));
		movies.add(new Movie("Balagam", "Konark", 107, "Book ASAP"));

		movieRepository.saveAll(movies);


		List<Role> roles = new ArrayList<>();
		roles.add(new Role(ERole.ROLE_ADMIN));
		roles.add(new Role(ERole.ROLE_USER));

		roleRepository.saveAll(roles);
	}
}
