FROM openjdk:17-alpine

EXPOSE 8080

ADD target/movieapp-0.0.1-SNAPSHOT.jar movieapp.jar

ENTRYPOINT ["java","-jar","/movieapp.jar"]